/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: main.c 
Description: The WPR application is a DPDK based pcap replay tool designed for high performance traffic generation from pcap files. Its built around the concept of dynamic 
traffic expansion via virtual clients, where a single pcap flow can be expanded into multiple flows by modifying packet headers on the fly. The main.c file contains the 
primary entry point for the DPDK application, handling initialization of DPDK EAL, loading configuration files, launching worker threads 
(control server, stats monitor, pcap loader, tx workers, buffer workers), and managing application shutdown.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <math.h> 
#include <cyaml/cyaml.h>

#include <rte_eal.h>
#include <rte_version.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <limits.h>
#include <arpa/inet.h>  // inet_pton, ntohl, htonl
#include <signal.h>

#include "wpr_control.h"
#include "wpr_app_defines.h"
#include "wpr_ports.h"
#include "wpr_stats.h"
#include "wpr_tx_worker.h"
#include "wpr_buff_worker.h"
#include "wpr_mbuf_fields.h"
#include "wpr_pcap_loader.h"
#include "wpr_config.h"
#include "wpr_acl.h"
#include "wpr_acl_db.h"
#include "wpr_acl_yaml.h"

//global force quit 
volatile sig_atomic_t force_quit = 0;
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = 1;
    }
}

//global error flag 
_Atomic int wpr_fatal_error = 0;

void wpr_fatal(const char *fmt, ...)
{
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_CRIT, "FATAL ERROR: %s", fmt);
    atomic_store_explicit(&wpr_fatal_error, 1, memory_order_release);
    force_quit = 1;
    
}

/* Declared in wpr_config.c main yaml parsing config schema */
extern const cyaml_schema_value_t wpr_config_schema;

/* Main entry point for DPDK application */
int main(int argc, char **argv) {

    int wpr_rc = 0; 

    //app ready is an atomic bool used to signal worker threads when app init is complete and safe to start
    _Atomic bool app_ready;
    atomic_store_explicit(&app_ready, false, memory_order_relaxed);

    unsigned int main_lcore_id=0; 
    cpu_set_t cpuset; 
    pthread_t control_server_thread;
    pthread_t stats_thread; 
    pthread_t pcap_loader_thread; 

    //start init, note we use WPR_LOG macro defined in wpr_log.h for all logging, this allows for different log levels and per module logging control
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\nPcap Replay Application Starting\n\n");

    /* Install signal handlers for clean shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        rte_exit(EXIT_FAILURE, "sigaction(SIGINT) failed\n");
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        rte_exit(EXIT_FAILURE, "sigaction(SIGTERM) failed\n");
    }


    /* ------------------------------------------------------ Init DPDK EAL ----------------------------------------------------------------- */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing DPDK EAL ###############################\n\n");
    //for any DPDK app, first thing we do is initialize the EAL (Environment Abstraction Layer) which sets up hugepages, memory, PMD's etc. 
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }

    //assumption today is all systems are NUMA single socket, so we get the socket id for future use
    int socket_id = rte_socket_id();
    
    //setup timestamp fields 
    int mbuf_time_offset;
    init_mbuf_tstamps(&mbuf_time_offset);

    //bump cli args based on number processed by EAL 
    argc -=ret;
    argv += ret;

    /* ------------------------------------------------------ Load config yaml file  --------------------------------------------------------- */
    //load application config from yaml file specified on command line, yaml parsing is done using libcymal library
    //libcyaml config schema is defined in wpr_config.c and wpr_config.h 
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Loading Application Configuration ###############################\n\n");

    //get config file path from eal arguments 
    const char *config_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[i + 1];
            i++;
        }
    }

    //use libcymal to parse log file into wpr_config_t struct 
    const cyaml_config_t cyaml_cfg = {
        .log_level = CYAML_LOG_WARNING,       /* adjust for debug */
        .mem_fn    = cyaml_mem,               /* default allocators */
        .log_fn    = cyaml_log,               /* default logger */
    };
    wpr_config_t *wpr_app_cfg = NULL;
    cyaml_err_t err = cyaml_load_file(config_file, &cyaml_cfg, &wpr_config_schema, (cyaml_data_t **)&wpr_app_cfg, NULL);
    if (err != CYAML_OK) {
        rte_exit(EXIT_FAILURE, "Cannot parse yaml config file %s\n",config_file);
    }
    

    unsigned int tx_cores      = wpr_app_cfg->thread_settings.tx_cores;
    unsigned int base_lcore_id = wpr_app_cfg->thread_settings.base_lcore_id;

    /* ------------------------------------------------------ Configure DPDK RCU QSBR Struct ---------------------------------------------------*/
    //multiple subsystems in wpr use RCU QSBR for safe memory reclamation of deferred objects (e.g. retired flow actions, load balancer nodes, etc.)
    //here we create the main RCU QSBR structure that will be shared with these subsystems. The RCU QSBR structure must know how many reader threads will be using it, so
    //we pass in the number of worker threads from config file. Note, the flow table manager thread is not a reader, so not included in this count.
    
    wpr_rcu_ctx_t *rcu_ctx = rte_zmalloc_socket("wpr_rcu_ctx",
                                sizeof(wpr_rcu_ctx_t),
                                RTE_CACHE_LINE_SIZE,
                                socket_id);
    if (!rcu_ctx){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for RCU QSBR context\n");
    }

    size_t qs_size = rte_rcu_qsbr_get_memsize(tx_cores);
    rcu_ctx->qs = rte_zmalloc_socket("wpr_rcu_qsbr",
                                qs_size,
                                RTE_CACHE_LINE_SIZE,
                                socket_id);
    if (!rcu_ctx->qs){
        rte_free(rcu_ctx);
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for RCU QSBR structure\n");
    }

    int rc = rte_rcu_qsbr_init(rcu_ctx->qs, tx_cores);
    if (rc != 0) {
        rte_free(rcu_ctx->qs);
        rcu_ctx->qs = NULL;
        return rc;
    }
    rcu_ctx->num_readers = tx_cores;

    /* ------------------------------------------------------ Initialize Mempools ---------------------------------------------------------------- */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Mempools ###############################\n\n"); 
    size_t priv_sz = RTE_ALIGN_CEIL(sizeof(wpr_priv_t), RTE_CACHE_LINE_SIZE);
    
    struct rte_mempool *pcap_mempool = NULL;
    struct rte_mempool **copy_mempools = rte_zmalloc("copy_mempools_array",
                                        sizeof(struct rte_mempool *) * tx_cores,
                                        RTE_CACHE_LINE_SIZE);
    if (!copy_mempools){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for copy mempool array\n");
    }

    //initialize each mempool from config file settings
    for (unsigned int i=0; i < wpr_app_cfg->mempool_settings_count; i++){
        wpr_mempool_t *mpool_cfg = &wpr_app_cfg->mempool_settings[i];

        //create the global pcap storage mempool 
        if (strcmp(mpool_cfg->name, "global_pcap_mempool") == 0){
            pcap_mempool = rte_pktmbuf_pool_create(mpool_cfg->name, mpool_cfg->mpool_entries,
                mpool_cfg->mpool_cache, priv_sz, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

            if (pcap_mempool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %s\n",mpool_cfg->name);

            WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Created global pcap mempool %s with %u entries\n",
                mpool_cfg->name, mpool_cfg->mpool_entries);

        }
        //else create per tx core copy pools 
        else if (strcmp(mpool_cfg->name, "copy_mempools") == 0){
            for(unsigned int i=0; i < tx_cores; i++){
                char mempool_name[64];
                snprintf(mempool_name, sizeof(mempool_name), "copy_mempool_core_%u", i);
                copy_mempools[i] = rte_pktmbuf_pool_create(mempool_name, mpool_cfg->mpool_entries,
                    mpool_cfg->mpool_cache, priv_sz, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

                if (copy_mempools[i] == NULL)
                    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %s\n",mempool_name);

                WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Created copy mempool %s with %u entries\n",
                    mempool_name, mpool_cfg->mpool_entries);
            }
        }

        else {
            rte_exit(EXIT_FAILURE, "Unknown mempool name %s in config\n",mpool_cfg->name);
        }
    }   

    /* ------------------------------------------------------ Configure ports --------------------------------------------------------------- */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Network Ports ###############################\n\n");
    
    //temporary variable to track total number of ports added to global port list
    unsigned int total_port_count = 0;

    //create the global port list array 
    wpr_ports_t *global_port_list = NULL;
    wpr_port_list_init(&global_port_list);
    if (global_port_list == NULL){
        rte_exit(EXIT_FAILURE, "Cannot create global port list\n");
    }

    //first we add all real DPDK Ethernet ports specified in the config file
    //the following loop performs the DPDK port initialization for each interface and adds an entry to the global port list
    //note, for real DPDK ports, we want a 1:1 mapping of rx/tx queues to worker cores. At runtime we determine if the NIC supports enough
    //queues to accomplish this. If not we request the maximum number of rx/tx queues per port and round robin assign them to worker cores (next step)
    
    //for each port specified in config file, initialize the port and add to global port list
    for (unsigned int i=0; i < wpr_app_cfg->port_settings_count; i++){
        
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Initializing NIC port %s\n",wpr_app_cfg->port_settings[i].name);
        wpr_port_t *port_cfg = &wpr_app_cfg->port_settings[i];

        /* -------------------------------- Initialize NIC Port from Config File ---------------------------------*/
        //convert pci bus address string to port id
        uint16_t dpdk_port_id;
        wpr_rc = wpr_get_port_id_by_pci_addr(port_cfg->pci_bus_addr, &dpdk_port_id);
        if (wpr_rc != 0){
            rte_exit(EXIT_FAILURE, "Cannot find port with pci bus address %s\n",port_cfg->pci_bus_addr);
        }
        
        //build a port config struct 
        wpr_portinit_cfg_t port_init_cfg;

        //we exclude our special manager worker core from normal port init since it won't directly interact with physical ports 
        uint16_t num_rx_queues = tx_cores;
        uint16_t num_tx_queues = tx_cores;

        port_init_cfg.num_rxq = num_rx_queues;
        port_init_cfg.num_txq = num_tx_queues;
        port_init_cfg.rx_ring_size = port_cfg->rx_ring_size;
        port_init_cfg.tx_ring_size = port_cfg->tx_ring_size;
        port_init_cfg.tx_ip_checksum_offload = port_cfg->tx_ip_checksum_offload;
        port_init_cfg.tx_tcp_checksum_offload = port_cfg->tx_tcp_checksum_offload;
        port_init_cfg.tx_udp_checksum_offload = port_cfg->tx_udp_checksum_offload;
        port_init_cfg.tx_multiseg_offload = port_cfg->tx_multiseg_offload;

        //add port list entry first with queues set to zero, init function will populate actual number of queues created and other metadata
        wpr_rc = wpr_portlist_add(global_port_list, port_cfg->name, dpdk_port_id, true, WPR_PORT_TYPE_ETHQ, num_rx_queues,num_tx_queues,WPR_PORT_RXTX);
        if (wpr_rc != 0){
            rte_exit(EXIT_FAILURE, "Cannot add port %s to global port list\n",port_cfg->name);
        }

        wpr_port_entry_t *port_entry = wpr_find_port_byid(global_port_list, dpdk_port_id);
        if (port_entry == NULL){
            rte_exit(EXIT_FAILURE, "Cannot find port entry for port %s after adding to global port list\n",port_cfg->name);
        }

        //initialize port and record the number of rx/tx queues that were actually created
        if (wpr_port_init(port_entry,dpdk_port_id, pcap_mempool, &port_init_cfg) != 0){
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",dpdk_port_id);
        }

        //initialize port stats
        wpr_port_stats_init(port_entry);

        //this is the index we use to reference this port externally in egress tables etc.
        uint16_t global_port_index = port_entry->global_port_index;

        total_port_count++;
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Successfully initialized port %s with DPDK port ID %"PRIu16" and global port index %"PRIu16"\n", 
            port_cfg->name, dpdk_port_id, global_port_index);
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\n");

    }

    wpr_portlist_print(global_port_list);

    /* ------------------------------------------------------ Initialize Global Policy Epochs ------------------------------------------------------- */
    //the WPR application is based around dynamic policy tables (egress table, ACL table etc) that can be updated at runtime.
    //the policy tables are cached in per worker core flow tables for performance. To ensure that worker cores always have the latest policy info,
    //we use an epoch based system. Each global policy table has an associated epoch counter that is incremented each time the table is updated.
    //Each worker core tracks the epoch of each policy table it has cached. When processing packets, if a worker core sees that the global epoch for
    //a given policy table is different than its cached epoch, it knows to refresh its cached policy info from that table. This allows for
    //efficient asynchronous policy updates without locking or complex synchronization between worker cores and control plane threads updating the policy tables.
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Global Policy Epochs ###############################\n");
    
    //create global policy epochs struct
    wpr_global_policy_epoch_t *global_policy_epochs = rte_zmalloc_socket("global_policy_epochs",
                                            sizeof(wpr_global_policy_epoch_t),
                                            RTE_CACHE_LINE_SIZE,
                                            socket_id);
    if (global_policy_epochs == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create global policy epochs struct\n");
    }

    //intialize all epochs to 1, separate epochs for each policy table
    //when a flow table entry is created, it caches the current epoch for each policy table
    //flow entries also indicate which policy table was the "decider" for the action applied to the packet
    //this allows us to only refresh the relevant policy table when epochs differ
    
    global_policy_epochs->acl_policy_epoch          = 1;   //the ACL ruleset has been updated
    global_policy_epochs->pcap_storage_epoch        = 1;   //the load balancer groupings have been updated 



    /* ------------------------------------------------------ Initialize ACL Table ---------------------------------------------------------- */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing ACL Table ###############################\n");
    
    //create an ACL database to hold runtime rules issued by the user 
    wpr_acl_rule_db_t wpr_acl_rules_db; 
    wpr_acl_rule_db_init (&wpr_acl_rules_db);

    //create a runtime context for ACL processing 
    uint32_t acl_qsbr_reclaim_trigger = wpr_app_cfg->acl_table_settings.qsbr_reclaim_size;
    uint32_t acl_qsbr_reclaim_limit   = wpr_app_cfg->acl_table_settings.qsbr_reclaim_limit;

    wpr_acl_runtime_t wpr_acl_runtime_ctx; 
    wpr_rc = wpr_acl_runtime_init(&wpr_acl_runtime_ctx, rte_socket_id(), rcu_ctx, global_policy_epochs,acl_qsbr_reclaim_trigger, acl_qsbr_reclaim_limit, tx_cores);
    if (wpr_rc != 0){
        rte_exit(EXIT_FAILURE, "Failed to initialize ACL runtime context\n");
    }

    //if a startup rules file was provided, load it now
    if (wpr_app_cfg->acl_table_settings.startup_cfg_file != NULL && wpr_app_cfg->acl_table_settings.startup_cfg_file[0] != '\0') {
        int rc = wpr_acl_load_startup_file(
            wpr_app_cfg->acl_table_settings.startup_cfg_file,
            &wpr_acl_rules_db,
            global_port_list,
            NULL);
        if (rc < 0) {
            rte_exit(EXIT_FAILURE, "Failed to load ACL startup rules file %s\n",
                wpr_app_cfg->acl_table_settings.startup_cfg_file);
        }
    }

    wpr_rc = wpr_acl_db_commit(&wpr_acl_runtime_ctx, &wpr_acl_rules_db);
    if (wpr_rc != 0){
        rte_exit(EXIT_FAILURE, "Failed to commit loaded ACL rules to runtime\n");
    }

    /* ------------------------------------------------------ Pcap Loader Init ----------------------------------------------- */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Pcap Loader ###############################\n\n");
    pcap_storage_t *global_pcap_storage = rte_zmalloc_socket("global_pcap_storage",
                                        sizeof(pcap_storage_t),
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (global_pcap_storage == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for global pcap storage\n");
    }

    pcap_loader_ctl_t *pcap_loader_ctl = rte_zmalloc_socket("pcap_loader_ctl",
                                        sizeof(pcap_loader_ctl_t),
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (pcap_loader_ctl == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for pcap loader controller\n");
    }


    /* ------------------------------------------------------ Build Tx Worker Contexts -----------------------------------------------*/
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing TX Worker Contexts ###############################\n\n");
    //create an array to hold all tx worker contexts
    wpr_tx_worker_ctx_t **tx_worker_ctx_array = rte_zmalloc_socket("tx_worker_ctx_array",
                                                sizeof(wpr_tx_worker_ctx_t *) * tx_cores,
                                                RTE_CACHE_LINE_SIZE,
                                                socket_id);

    if(tx_worker_ctx_array == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for tx worker context array\n");
    }

    //create a per port global stream config array
    wpr_port_stream_global_t *port_stream_global_cfg = rte_zmalloc_socket("port_stream_global_cfg",
                                                sizeof(wpr_port_stream_global_t) * global_port_list->num_ports,
                                                RTE_CACHE_LINE_SIZE,
                                                socket_id);
    if (port_stream_global_cfg == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for port stream global config array\n");
    }

    for (unsigned int port_idx = 0; port_idx < global_port_list->num_ports; port_idx++){
        wpr_port_stream_global_t *g = &port_stream_global_cfg[port_idx];
        g->max_clients = tx_cores * MAX_VC_PER_WORKER;
        g->run_seed = 0; 
        atomic_store_explicit(&g->active_clients, 1, memory_order_release);
        atomic_store_explicit(&g->slot_id, UINT32_MAX, memory_order_release); //no slot assigned yet

        g->pace_mode = VC_PACE_NONE;
        g->start_mode = VC_START_FIXED_INDEX;

        g->global_start_ns = 0;
        g->replay_window_ns = 0;

        //initialize the idp struct
        // src: 10.(port_idx).0.1  .. 10.(port_idx).255.254
        g->idp.src_ip_lo = RTE_IPV4(10, port_idx & 0xFF, 0, 1);
        g->idp.src_ip_hi = RTE_IPV4(10, port_idx & 0xFF, 255, 254);

        // src: 11.(port_idx).0.1  .. 11.(port_idx).255.254
        g->idp.dst_ip_lo = RTE_IPV4(11, port_idx & 0xFF, 0, 1);
        g->idp.dst_ip_hi = RTE_IPV4(11, port_idx & 0xFF, 255, 254);
        
        // ports: 49152 - 65535 ephemeral range
        g->idp.src_port_lo = 49152;
        g->idp.src_port_hi = 65535;

        //this will probably not be used, but set to some value
        g->idp.dst_port_lo = 0;
        g->idp.dst_port_hi = 500;
        
        g->idp.src_mac_base[0] = 0x02;  // LAA + unicast
        g->idp.src_mac_base[1] = port_idx;
        g->idp.src_mac_base[2] = 0x00;
        g->idp.src_mac_base[3] = 0x00;
        g->idp.src_mac_base[4] = 0x00;
        g->idp.src_mac_base[5] = 0x00;

        g->idp.dst_mac_base[0] = 0x02;
        g->idp.dst_mac_base[1] = 0x11;
        g->idp.dst_mac_base[2] = 0x00;
        g->idp.dst_mac_base[3] = 0x00;
        g->idp.dst_mac_base[4] = 0x00;
        g->idp.dst_mac_base[5] = 0x00;

        g->idp.mac_stride = 1;
    }   


    //create and initialize each worker context 
    for (unsigned int core_idx = 0; core_idx < tx_cores; core_idx++){
        tx_worker_ctx_array[core_idx] = rte_zmalloc_socket("wpr_tx_worker_ctx",
                                                sizeof(wpr_tx_worker_ctx_t),
                                                RTE_CACHE_LINE_SIZE,
                                                socket_id);
        if (tx_worker_ctx_array[core_idx] == NULL){
            rte_exit(EXIT_FAILURE, "Cannot allocate memory for tx worker context\n");
        }

        tx_worker_ctx_array[core_idx]->worker_id             = core_idx;
        tx_worker_ctx_array[core_idx]->run_seed              = 0;
        tx_worker_ctx_array[core_idx]->num_ports             = global_port_list->num_ports;

        for (unsigned int port_idx = 0; port_idx < global_port_list->num_ports; port_idx++){
            
            //initialize per worker/port stream context
            wpr_port_stream_ctx_t *port_stream = &tx_worker_ctx_array[core_idx]->port_stream[port_idx];
            port_stream->clients = rte_zmalloc("wpr_vc_ctx_array",
                                        sizeof(wpr_vc_ctx_t) * MAX_VC_PER_WORKER,
                                        RTE_CACHE_LINE_SIZE);
            if (port_stream->clients == NULL){
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for virtual client context array\n");
            }
 
            port_stream->num_clients = 0;
            port_stream->last_start_gid = UINT32_MAX;
            port_stream->last_count = UINT32_MAX;
            port_stream->global_cfg = &port_stream_global_cfg[port_idx];
            port_stream->rr_next_client = 0;


            //initialize port map per worker 
            wpr_port_worker_map_t *map = &tx_worker_ctx_array[core_idx]->map_by_port[port_idx];
            map->W = tx_cores;
            map->rank = core_idx;

            //every worker needs its own queue for tx 
            uint16_t *queue_id_by_port = &tx_worker_ctx_array[core_idx]->queue_id_by_port[port_idx];
            *queue_id_by_port = core_idx;

        }

    }

    /* ------------------------------------------------------ Build and Launch Threads -----------------------------------------------*/
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Launching Worker Threads ###############################\n\n");
    /* Worker Tx Threads */
    wpr_thread_args_t **tx_thread_args_array = rte_zmalloc_socket("tx_thread_args_array",
                                                sizeof(wpr_thread_args_t *) * tx_cores,
                                                RTE_CACHE_LINE_SIZE,
                                                socket_id);
    if (tx_thread_args_array == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for tx thread args array\n");
    }

    for (unsigned int core_idx = 0; core_idx < tx_cores; core_idx++){
        tx_thread_args_array[core_idx] = rte_zmalloc_socket("tx_thread_args",
                                                sizeof(wpr_thread_args_t),
                                                RTE_CACHE_LINE_SIZE,
                                                socket_id);
        if (tx_thread_args_array[core_idx] == NULL){
            rte_exit(EXIT_FAILURE, "Cannot allocate memory for tx thread args\n");
        }   

        //identifiers
        tx_thread_args_array[core_idx]->core_id          = base_lcore_id + core_idx;
        tx_thread_args_array[core_idx]->thread_index     = core_idx;
        tx_thread_args_array[core_idx]->num_tx_cores     = tx_cores;
        tx_thread_args_array[core_idx]->poll_period_ms   = 0;           //not used for tx worker 
        atomic_store_explicit(&tx_thread_args_array[core_idx]->thread_ready, 0, memory_order_release);
        tx_thread_args_array[core_idx]->app_ready        = &app_ready;

        //traffic gen control / status 
        tx_thread_args_array[core_idx]->tx_worker_ctx           = tx_worker_ctx_array[core_idx];
        tx_thread_args_array[core_idx]->port_stream_global_cfg  = port_stream_global_cfg;
        tx_thread_args_array[core_idx]->mbuf_ts_off             = mbuf_time_offset;

        //stats & control interfaces
        tx_thread_args_array[core_idx]->global_port_list = global_port_list;
        tx_thread_args_array[core_idx]->global_stats     = NULL;        //not used for tx worker

        //pcap loader / storage interfaces 
        tx_thread_args_array[core_idx]->pcap_controller  = NULL;        //not used for tx worker
        tx_thread_args_array[core_idx]->pcap_storage     = global_pcap_storage;

        //mempool pointers
        tx_thread_args_array[core_idx]->pcap_template_mpool = pcap_mempool;
        tx_thread_args_array[core_idx]->txcore_copy_mpools  = copy_mempools[core_idx];

        //QSBR Context
        tx_thread_args_array[core_idx]->rcu_ctx          = NULL;       //not used for tx worker

        //acl rules interface 
        tx_thread_args_array[core_idx]->acl_runtime = &wpr_acl_runtime_ctx;
        tx_thread_args_array[core_idx]->acl_rule_db = &wpr_acl_rules_db;
    }

    //launch non core 0 datapath cores
    for (unsigned int thread_idx = 0; thread_idx < tx_cores; thread_idx++){
        //launch core
        rte_eal_remote_launch(run_tx_worker, tx_thread_args_array[thread_idx], tx_thread_args_array[thread_idx]->core_id);
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\tLaunched worker core %d on lcore %d\n", thread_idx, tx_thread_args_array[thread_idx]->core_id);
    }


    /* Set main thread affinity to main lcore */
    CPU_ZERO(&cpuset);
    CPU_SET(main_lcore_id, &cpuset);


    /* Stats pthread */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Launching Stats Manager Thread ###############################\n\n");
    wpr_thread_args_t *stats_thread_args = rte_zmalloc_socket("stats_thread_args",
                                        sizeof(wpr_thread_args_t),
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (stats_thread_args == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for stats thread args\n");
    }

    //identifiers
    stats_thread_args->core_id          = 0;
    stats_thread_args->thread_index     = 0;
    stats_thread_args->num_tx_cores     = tx_cores;
    stats_thread_args->poll_period_ms   = 500; 
    atomic_store_explicit(&stats_thread_args->thread_ready, 0, memory_order_release);
    stats_thread_args->app_ready        = &app_ready;

    //traffic gen control / status 
    stats_thread_args->tx_worker_ctx           = NULL;              //Not Used
    stats_thread_args->port_stream_global_cfg  = port_stream_global_cfg;              
    stats_thread_args->mbuf_ts_off             = mbuf_time_offset;           

    //stats & control interfaces
    stats_thread_args->global_port_list = global_port_list;
    stats_thread_args->global_stats     = NULL;        //to be implemented

    //pcap loader / storage interfaces
    stats_thread_args->pcap_controller  = NULL;         //Not Used
    stats_thread_args->pcap_storage     = NULL;         //Not Used

    //mempool pointers 
    stats_thread_args->pcap_template_mpool = pcap_mempool; 
    stats_thread_args->txcore_copy_mpools  = copy_mempools[0];

    //QSBR Context 
    stats_thread_args->rcu_ctx          = rcu_ctx;

    //acl rules interface
    stats_thread_args->acl_runtime = &wpr_acl_runtime_ctx;
    stats_thread_args->acl_rule_db = &wpr_acl_rules_db;


    //launch stats thread and pin to core 0
    if (pthread_create(&stats_thread, NULL, run_wpr_stats_thread, stats_thread_args) != 0){
        rte_exit(EXIT_FAILURE, "stats thread creation failed\n");
    }
    if (pthread_setaffinity_np(stats_thread, sizeof(cpu_set_t), &cpuset) != 0){
        rte_exit(EXIT_FAILURE, "pthread_setaffinity_np failed for stats monitor thread\n");
    }

    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\t Stats Manager thread launched on core %d\n", main_lcore_id);


    /* Pcap Loader pthread */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Launching Pcap Loader Thread ###############################\n\n");

    wpr_thread_args_t *pload_thread_args = rte_zmalloc_socket("pload_thread_args",
                                        sizeof(wpr_thread_args_t),
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (pload_thread_args == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for pload thread args\n");
    }

    //identifiers
    pload_thread_args->core_id          = 0;
    pload_thread_args->thread_index     = 0;
    pload_thread_args->num_tx_cores     = tx_cores;
    pload_thread_args->poll_period_ms   = 500; 
    atomic_store_explicit(&pload_thread_args->thread_ready, 0, memory_order_release);
    pload_thread_args->app_ready        = &app_ready;

    //traffic gen control / status 
    pload_thread_args->tx_worker_ctx           = NULL;              //Not Used
    pload_thread_args->port_stream_global_cfg  = port_stream_global_cfg;            
    pload_thread_args->mbuf_ts_off             = mbuf_time_offset;           

    //pload & control interfaces
    pload_thread_args->global_port_list = global_port_list;
    pload_thread_args->global_stats     = NULL;        //to be implemented

    //pcap loader / storage interfaces
    pload_thread_args->pcap_controller  = pcap_loader_ctl;         //Not Used
    pload_thread_args->pcap_storage     = global_pcap_storage;         //Not Used

    //mempool pointers 
    pload_thread_args->pcap_template_mpool = pcap_mempool; 
    pload_thread_args->txcore_copy_mpools  = copy_mempools[0];

    //QSBR Context 
    pload_thread_args->rcu_ctx          = rcu_ctx;

    //acl rules interface
    pload_thread_args->acl_runtime = &wpr_acl_runtime_ctx;
    pload_thread_args->acl_rule_db = &wpr_acl_rules_db;

    //launch stats thread and pin to core 0
    if (pthread_create(&pcap_loader_thread, NULL, run_pcap_loader_thread, pload_thread_args) != 0){
        rte_exit(EXIT_FAILURE, "pcap loader thread creation failed\n");
    }
    if (pthread_setaffinity_np(pcap_loader_thread, sizeof(cpu_set_t), &cpuset) != 0){
        rte_exit(EXIT_FAILURE, "pthread_setaffinity_np failed for pcap loader monitor thread\n");
    }

    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\t Pcap Loader thread launched on core %d\n", main_lcore_id);


    /* Control Server pthread */
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Launching Control Server Thread ###############################\n\n");

    wpr_thread_args_t *control_server_thread_args = rte_zmalloc_socket("control_server_thread_args",
                                        sizeof(wpr_thread_args_t),
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (control_server_thread_args == NULL){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for control server thread args\n");
    }

    //identifiers
    control_server_thread_args->core_id          = 0;
    control_server_thread_args->thread_index     = 0;
    control_server_thread_args->num_tx_cores     = tx_cores;
    control_server_thread_args->poll_period_ms   = 500; 
    atomic_store_explicit(&control_server_thread_args->thread_ready, 0, memory_order_release);
    control_server_thread_args->app_ready        = &app_ready;
    //traffic gen control / status 
    control_server_thread_args->tx_worker_ctx           = NULL;              //Not Used
    control_server_thread_args->port_stream_global_cfg  = port_stream_global_cfg;        
    control_server_thread_args->mbuf_ts_off             = mbuf_time_offset;           

    //pload & control interfaces
    control_server_thread_args->global_port_list = global_port_list;
    control_server_thread_args->global_stats     = NULL;        //to be implemented

    //pcap loader / storage interfaces
    control_server_thread_args->pcap_controller  = pcap_loader_ctl;      
    control_server_thread_args->pcap_storage     = global_pcap_storage;         

    //mempool pointers 
    control_server_thread_args->pcap_template_mpool = pcap_mempool; 
    control_server_thread_args->txcore_copy_mpools  = copy_mempools[0];

    //QSBR Context 
    control_server_thread_args->rcu_ctx          = rcu_ctx;

    //acl rules interface
    control_server_thread_args->acl_runtime = &wpr_acl_runtime_ctx;
    control_server_thread_args->acl_rule_db = &wpr_acl_rules_db;

    control_server_thread_args->controller_port = wpr_app_cfg->app_settings.controller_port;

    //launch stats thread and pin to core 0
    if (pthread_create(&control_server_thread, NULL, run_wpr_app_server_thread, control_server_thread_args) != 0){
        rte_exit(EXIT_FAILURE, "control server thread creation failed\n");
    }
    if (pthread_setaffinity_np(control_server_thread, sizeof(cpu_set_t), &cpuset) != 0){
        rte_exit(EXIT_FAILURE, "pthread_setaffinity_np failed for control server thread\n");
    }

    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "\t Control Server thread launched on core %d\n", main_lcore_id);

    
    /* ------------------------------------------------------ Wait for all threads to initialize ------------------------------------------------------- */
    //now that we've launched all threads, we don't want to start accepting packets until everyone is ready. First we poll for each thread 
    //to signal they've reached their init complete state. Then main singles back to all threads that they are clear to start running. 

    //poll for all threads to be ready
    bool is_app_ready = false;
    while (is_app_ready == false && !force_quit && wpr_fatal_error == false) {
        bool all_worker_ready = true;

        //tx threads
        for (unsigned int i=0; i < tx_cores; i++){
            if (atomic_load_explicit(&tx_thread_args_array[i]->thread_ready, memory_order_relaxed) == false) {
                all_worker_ready = false;
                break;
            }
        }

        //stats thread
        if(atomic_load_explicit(&stats_thread_args->thread_ready, memory_order_relaxed) == false) {
            all_worker_ready = false;
        }

        //pcap loader thread 
        if(atomic_load_explicit(&pload_thread_args->thread_ready, memory_order_relaxed) == false) {
            all_worker_ready = false;
        }   
        //control server 
        if(atomic_load_explicit(&control_server_thread_args->thread_ready, memory_order_relaxed) == false) {
            all_worker_ready = false;
        }   

        if (all_worker_ready) {
            is_app_ready = true;

        } else {    
            rte_delay_us_sleep(100);
        }
    }


    //now that all threads have ack'd they are ready, signal them to start processing via the global app_ready flag.
    //local threads
    atomic_store_explicit(&app_ready, true, memory_order_relaxed);

    //bring up all configured external links 
    for (unsigned int i=0; i < global_port_list->num_ports; i++){
        wpr_port_entry_t *port_entry = &global_port_list->ports[i];
        
        //if the port is external, bring it up now 
        if(port_entry->is_external == true ){
            wpr_rc = wpr_port_set_link_state(port_entry, true);
            if (wpr_rc != 0){
                WPR_LOG(WPR_LOG_INIT, RTE_LOG_WARNING, "Failed to bring up link for port %s\n",port_entry->name);
            } else {
                WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Brought up link for port %s\n",port_entry->name);
            }
        }
    }

    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### All threads initialized, starting processing ###############################\n\n");

    //wait and clean up
    pthread_join(stats_thread, NULL);
    pthread_join(pcap_loader_thread, NULL);
    pthread_join(control_server_thread, NULL);
    rte_eal_mp_wait_lcore();

    uint16_t shutdown_port_id;
    WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### WPR Application Exiting ###############################\n");

    
    
    RTE_ETH_FOREACH_DEV(shutdown_port_id) {
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Stopping port %u\n", shutdown_port_id);
        rte_eth_dev_stop(shutdown_port_id);
    }

    RTE_ETH_FOREACH_DEV(shutdown_port_id) {
        WPR_LOG(WPR_LOG_INIT, RTE_LOG_INFO, "Closing port %u\n", shutdown_port_id);
        rte_eth_dev_close(shutdown_port_id);
    }
    
    //clean up and exit 
    rte_free(control_server_thread_args);
    rte_free(pload_thread_args);
    rte_free(stats_thread_args);

    for (unsigned int i=0; i < tx_cores; i++){
        rte_free(tx_thread_args_array[i]);
        rte_free(tx_worker_ctx_array[i]->port_stream[0].clients); //all port streams share same clients ptr
        rte_free(tx_worker_ctx_array[i]);
    }   
    rte_free(tx_thread_args_array);
    rte_free(port_stream_global_cfg);
    rte_free(global_pcap_storage);
    rte_free(pcap_loader_ctl);
    wpr_acl_runtime_deinit(&wpr_acl_runtime_ctx);
    rte_free(global_policy_epochs);
    wpr_port_list_free(global_port_list);
    
    rte_mempool_free(pcap_mempool);
    for (unsigned int i=0; i < tx_cores; i++){
        rte_mempool_free(copy_mempools[i]);
    }
    rte_free(copy_mempools);
    if (rcu_ctx) {
        if (rcu_ctx->qs)
            rte_free(rcu_ctx->qs);
        rte_free(rcu_ctx);
    }

    //cyaml 
    cyaml_free(&cyaml_cfg, &wpr_config_schema, (cyaml_data_t *)wpr_app_cfg, 0);

    //eal cleanup 
    rte_eal_cleanup();

    printf("Application exiting cleanly");
    return 0;
}
