/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: main.c 
Description: 
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>
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

#include "ppr_control.h"
#include "ppr_app_defines.h"
#include "ppr_ports.h"
#include "ppr_stats.h"
#include "ppr_tx_worker.h"
#include "ppr_buff_worker.h"
#include "ppr_mbuf_fields.h"
#include "ppr_pcap_loader.h"
#include "ppr_config.h"
#include "ppr_acl.h"
#include "ppr_acl_db.h"
#include "ppr_acl_yaml.h"

//global force quit 
volatile sig_atomic_t force_quit = 0;
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = 1;
    }
}

//global error flag 
_Atomic int ppr_fatal_error = 0;

void ppr_fatal(const char *fmt, ...)
{
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_CRIT, "FATAL ERROR: %s", fmt);
    atomic_store_explicit(&ppr_fatal_error, 1, memory_order_release);
    force_quit = 1;
    
}

/* Declared in ppr_config.c main yaml parsing config schema */
extern const cyaml_schema_value_t ppr_config_schema;

/* Main entry point for DPDK application */
int main(int argc, char **argv) {

    int ppr_rc = 0; 


    unsigned int main_lcore_id; 
    cpu_set_t cpuset; 
    pthread_t controller_thread;
    pthread_t stats_thread; 
    pthread_t pcap_loader_thread; 

    struct rte_mempool *app_mempool             = NULL;
    struct rte_mempool **core_clone_mempools    = NULL; 

    //start init, note we use PPR_LOG macro defined in ppr_log.h for all logging, this allows for different log levels and per module logging control
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "\nPcap Replay Application Starting\n\n");
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing DPDK EAL ###############################\n\n");

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


    /* -------------------------- Init DPDK EAL ----------------------------------------------------------------- */
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

    /* -------------------------- Load config yaml file  --------------------------------------------------------- */
    //load application config from yaml file specified on command line, yaml parsing is done using libcymal library
    //libcyaml config schema is defined in ppr_config.c and ppr_config.h 
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Loading Application Configuration ###############################\n\n");
    //get config file path from eal arguments 
    const char *config_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[i + 1];
            i++;
        }
    }

    //use libcymal to parse log file into ppr_config_t struct 
    const cyaml_config_t cyaml_cfg = {
        .log_level = CYAML_LOG_WARNING,       /* adjust for debug */
        .mem_fn    = cyaml_mem,               /* default allocators */
        .log_fn    = cyaml_log,               /* default logger */
    };
    ppr_config_t *ppr_app_cfg = NULL;
    cyaml_err_t err = cyaml_load_file(config_file, &cyaml_cfg, &ppr_config_schema, (cyaml_data_t **)&ppr_app_cfg, NULL);
    if (err != CYAML_OK) {
        rte_exit(EXIT_FAILURE, "Cannot parse yaml config file %s\n",config_file);
    }
    

    unsigned int tx_cores     = ppr_app_cfg->thread_settings.tx_cores;

    /* ------------------------- Configure DPDK RCU QSBR Struct ---------------------------------------------------*/
    //multiple subsystems in ppr use RCU QSBR for safe memory reclamation of deferred objects (e.g. retired flow actions, load balancer nodes, etc.)
    //here we create the main RCU QSBR structure that will be shared with these subsystems. The RCU QSBR structure must know how many reader threads will be using it, so
    //we pass in the number of worker threads from config file. Note, the flow table manager thread is not a reader, so not included in this count.
    
    ppr_rcu_ctx_t *rcu_ctx = rte_zmalloc_socket("ppr_rcu_ctx",
                                sizeof(ppr_rcu_ctx_t),
                                RTE_CACHE_LINE_SIZE,
                                socket_id);
    if (!rcu_ctx){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for RCU QSBR context\n");
    }

    size_t qs_size = rte_rcu_qsbr_get_memsize(tx_cores);
    rcu_ctx->qs = rte_zmalloc_socket("ppr_rcu_qsbr",
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

    /* -------------------------- Initialize Mempools ---------------------------------------------------------------- */
    size_t priv_sz = RTE_ALIGN_CEIL(sizeof(ppr_priv_t), RTE_CACHE_LINE_SIZE);
    
    struct rte_mempool *pcap_mempool = NULL;
    struct rte_mempool **copy_mempools = rte_zmalloc("copy_mempools_array",
                                        sizeof(struct rte_mempool *) * tx_cores,
                                        RTE_CACHE_LINE_SIZE);
    if (!copy_mempools){
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for copy mempool array\n");
    }

    //initialize each mempool from config file settings
    for (unsigned int i=0; i < ppr_app_cfg->mempool_settings_count; i++){
        ppr_mempool_t *mpool_cfg = &ppr_app_cfg->mempool_settings[i];

        //create the global pcap storage mempool 
        if (strcmp(mpool_cfg->name, "global_pcap_mempool") == 0){
            pcap_mempool = rte_pktmbuf_pool_create(mpool_cfg->name, mpool_cfg->mpool_entries,
                mpool_cfg->mpool_cache, priv_sz, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

            if (pcap_mempool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %s\n",mpool_cfg->name);

            PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "Created global pcap mempool %s with %u entries\n",
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

                PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "Created copy mempool %s with %u entries\n",
                    mempool_name, mpool_cfg->mpool_entries);
            }
        }

        else {
            rte_exit(EXIT_FAILURE, "Unknown mempool name %s in config\n",mpool_cfg->name);
        }
    }   


    /* -------------------------- Configure ports --------------------------------------------------------------- */
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Network Ports ###############################\n\n");
    
    //temporary variable to track total number of ports added to global port list
    unsigned int total_port_count = 0;

    //create the global port list array 
    ppr_ports_t *global_port_list = NULL;
    ppr_port_list_init(&global_port_list);
    if (global_port_list == NULL){
        rte_exit(EXIT_FAILURE, "Cannot create global port list\n");
    }

    //first we add all real DPDK Ethernet ports specified in the config file
    //the following loop performs the DPDK port initialization for each interface and adds an entry to the global port list
    //note, for real DPDK ports, we want a 1:1 mapping of rx/tx queues to worker cores. At runtime we determine if the NIC supports enough
    //queues to accomplish this. If not we request the maximum number of rx/tx queues per port and round robin assign them to worker cores (next step)
    
    //for each port specified in config file, initialize the port and add to global port list
    for (unsigned int i=0; i < ppr_app_cfg->port_settings_count; i++){
        
        PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "Initializing NIC port %s\n",ppr_app_cfg->port_settings[i].name);
        ppr_port_t *port_cfg = &ppr_app_cfg->port_settings[i];

        /* -------------------------------- Initialize NIC Port from Config File ---------------------------------*/
        //convert pci bus address string to port id
        uint16_t dpdk_port_id;
        ppr_rc = ppr_get_port_id_by_pci_addr(port_cfg->pci_bus_addr, &dpdk_port_id);
        if (ppr_rc != 0){
            rte_exit(EXIT_FAILURE, "Cannot find port with pci bus address %s\n",port_cfg->pci_bus_addr);
        }
        
        //build a port config struct 
        ppr_portinit_cfg_t port_init_cfg;

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
        ppr_rc = ppr_portlist_add(global_port_list, port_cfg->name, dpdk_port_id, true, PPR_PORT_TYPE_ETHQ, num_rx_queues,num_tx_queues,PPR_PORT_RXTX);
        if (ppr_rc != 0){
            rte_exit(EXIT_FAILURE, "Cannot add port %s to global port list\n",port_cfg->name);
        }

        ppr_port_entry_t *port_entry = ppr_find_port_byid(global_port_list, dpdk_port_id);
        if (port_entry == NULL){
            rte_exit(EXIT_FAILURE, "Cannot find port entry for port %s after adding to global port list\n",port_cfg->name);
        }

        //initialize port and record the number of rx/tx queues that were actually created
        if (ppr_port_init(port_entry,dpdk_port_id, app_mempool, &port_init_cfg) != 0){
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",dpdk_port_id);
        }

        //initialize port stats
        ppr_port_stats_init(port_entry);

        //this is the index we use to reference this port externally in egress tables etc.
        uint16_t global_port_index = port_entry->global_port_index;

        total_port_count++;
        PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "Successfully initialized port %s with DPDK port ID %"PRIu16" and global port index %"PRIu16"\n", 
            port_cfg->name, dpdk_port_id, global_port_index);
        PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, "\n");

    }

    /* -------------------------- Initialize Global Policy Epochs ------------------------------------------------------- */
    //the PPR application is based around dynamic policy tables (egress table, ACL table etc) that can be updated at runtime.
    //the policy tables are cached in per worker core flow tables for performance. To ensure that worker cores always have the latest policy info,
    //we use an epoch based system. Each global policy table has an associated epoch counter that is incremented each time the table is updated.
    //Each worker core tracks the epoch of each policy table it has cached. When processing packets, if a worker core sees that the global epoch for
    //a given policy table is different than its cached epoch, it knows to refresh its cached policy info from that table. This allows for
    //efficient asynchronous policy updates without locking or complex synchronization between worker cores and control plane threads updating the policy tables.
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing Global Policy Epochs ###############################\n");
    
    //create global policy epochs struct
    ppr_global_policy_epoch_t *global_policy_epochs = rte_zmalloc_socket("global_policy_epochs",
                                            sizeof(ppr_global_policy_epoch_t),
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



    /* -------------------------- Initialize ACL Table ---------------------------------------------------------- */
    PPR_LOG(PPR_LOG_INIT, RTE_LOG_INFO, 
        "\n############################### Initializing ACL Table ###############################\n");
    
    //create an ACL database to hold runtime rules issued by the user 
    ppr_acl_rule_db_t ppr_acl_rules_db; 
    ppr_acl_rule_db_init (&ppr_acl_rules_db);

    //create a runtime context for ACL processing 
    uint32_t acl_qsbr_reclaim_trigger = ppr_app_cfg->acl_table_settings.qsbr_reclaim_size;
    uint32_t acl_qsbr_reclaim_limit   = ppr_app_cfg->acl_table_settings.qsbr_reclaim_limit;

    ppr_acl_runtime_t ppr_acl_runtime_ctx; 
    ppr_rc = ppr_acl_runtime_init(&ppr_acl_runtime_ctx, rte_socket_id(), rcu_ctx, global_policy_epochs,acl_qsbr_reclaim_trigger, acl_qsbr_reclaim_limit, tx_cores);
    if (ppr_rc != 0){
        rte_exit(EXIT_FAILURE, "Failed to initialize ACL runtime context\n");
    }

    //if a startup rules file was provided, load it now
    if (ppr_app_cfg->acl_table_settings.startup_cfg_file != NULL && ppr_app_cfg->acl_table_settings.startup_cfg_file[0] != '\0') {
        int rc = ppr_acl_load_startup_file(
            ppr_app_cfg->acl_table_settings.startup_cfg_file,
            &ppr_acl_rules_db,
            global_port_list);
        if (rc < 0) {
            rte_exit(EXIT_FAILURE, "Failed to load ACL startup rules file %s\n",
                ppr_app_cfg->acl_table_settings.startup_cfg_file);
        }
    }

    ppr_rc = ppr_acl_db_commit(&ppr_acl_runtime_ctx, &ppr_acl_rules_db);
    if (ppr_rc != 0){
        rte_exit(EXIT_FAILURE, "Failed to commit loaded ACL rules to runtime\n");
    }

    /* -------------------------- Global Stats Init ----------------------------------------------- */



    /* -------------------------- Pcap Loader Init ----------------------------------------------- */



    /* -------------------------- Build and Launch Threads -----------------------------------------------*/
    
    /* Worker Tx Threads */

    /* Stats pthread */

    /* Pcap Loader pthread */

    /* Control Server pthread */

    /* -------------------------- Launch sevice pthreads that run on the main core ---------------------- */

    //Configure and Launch support pthreads on main core 
    //pin pthreads to main core 
    CPU_ZERO(&cpuset);
    CPU_SET(main_lcore_id, &cpuset);


    
    /* -------------------------- Mark app as initialized, end of init thread until exit ------------------ */

    //mark app as initialized 

    //wait and clean up
    rte_eal_mp_wait_lcore();

    printf("Application exiting cleanly");
    return 0;
}
