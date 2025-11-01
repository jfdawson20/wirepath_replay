/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: main.c 
Description: Primary entry point for the Pcap Replay DPDK dataplane application. The high level flow of this code is as follows: 
1) Load config file - the Pcap Replay dataplane uses the same exact config.json file used by the paired python code to keep config sources in sync. 
2) Allocate tx and buffer core ID's - To keep things as generic as possible, the config file only specifies the number of tx cores and the total core count. 
   After loading these fields, the application dynamically figures out which core ID's to map to tx threads and how many buffer threads should map to each 
   tx core. 
3) Mempool creation - DPDK memory pools are created for pcap template storage as well as separate clone only mempools (initialized for mbuff header storage only)
   for each tx core identified above. 
4) Initialize all ports passed into the DPDK application from the CLI args. Note, this app is designed to operate on VF ports to provide the most flexibility 
   of transmit control. The application assumes rate limiting is supported per VF port in hardware and handled outside of the actual datapath. 
5) Shared memory initialization - there are a number of shared memory structures for passing state, statistics, and control parameters between DPDK and pthreads
   and to relay command / control / status from python services via the socket based control server 
6) Launch Tx and Buffer lcore threads - spawn dedicated tx and buffer DPDK workers on assigned cores. 
7) Launch Control / Statistics / Pcap_Loader pthreads. 

At the end the master thread sits idle as all other spawned threads performed their allocated work assignments. 
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>

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
#include <rte_ring.h>
#include <limits.h>
#include <arpa/inet.h>  // inet_pton, ntohl, htonl

#include "control.h"
#include "app_defines.h"
#include "ports.h"
#include "stats.h"
#include "tx_worker.h"
#include "buff_worker.h"
#include "mbuf_fields.h"
#include "flowtable.h"



/* Main entry point for DPDK application */
int main(int argc, char **argv) {

    unsigned int main_lcore_id; 
    cpu_set_t cpuset; 
    pthread_t controller_thread;
    pthread_t stats_thread; 
    pthread_t pcap_loader_thread; 
    pthread_t ft_manager_thread; 
    unsigned int ctl_port = 9000; 
    unsigned int stats_poll_rate_ms = 500; 
    json_t *config_root;
    json_error_t config_error;

    struct rte_mempool *app_mempool = NULL;
    struct rte_mempool **core_clone_mempools = NULL; 

    //shared memory structures for stats and app state 
    struct psmith_stats_all *shared_app_stats;
    struct psmith_app_state *shared_app_state; 

    //init the DPDK environment abstraction layer 
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }

    uint64_t tsc_hz = rte_get_tsc_hz();
    
    int mbuf_time_offset;
    init_mbuf_tstamps(&mbuf_time_offset);
    //bump cli args based on number processed by EAL 
    argc -=ret;
    argv += ret;

    /* -------------------------- Load config json file  --------------------------------------------------------- */

    const char *config_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[i + 1];
            i++;
        }
    }    

    printf("config file: %s\n",config_file);
    //load config file 
    config_root = json_load_file(config_file,0,&config_error);
    if (!config_root){
        rte_exit(EXIT_FAILURE,"Failed to load config json file %s: %s\n",config_file,config_error.text);
    }

    //extract the core config parameters from the config file 
    json_t *core_cfg = json_object_get(config_root, "core_config");
    int tx_cores = (int)json_integer_value(json_object_get(core_cfg, "tx_cores"));
    int max_buff_fillers = (int)json_integer_value(json_object_get(core_cfg, "limit_buf_cores"));

    //compute filler to tx core assignmnts 
    unsigned int core_count = rte_lcore_count();
    RTE_LOG(INFO, EAL, "DPDK sees %u lcores\n", core_count);

    //init struct to track tx <-> filler core mapping 
    //assume no more that 256 theads per tx core... 
    struct core_mapping *core_map = calloc(tx_cores,sizeof(struct core_mapping));
    for (int i=0; i<tx_cores; i++){
        core_map[i].tx_core = i+2;
        core_map[i].filler_cores = calloc(256, sizeof(int));
        core_map[i].total_fillers = 0;
    }

    //make sure we have a minimum number of cores
    if ((core_count - 2 - tx_cores) < tx_cores){
        rte_exit(EXIT_FAILURE,"Insufficent Filler Cores Available");
    }

    //calculate maximum core id 
    int buffs_per_core = ((core_count - 2 - tx_cores) / tx_cores);
    int max_buff_id    = buffs_per_core * tx_cores;

    printf("buffs_per_core: %d\n",buffs_per_core);
    printf("max_buff_id: %d\n",max_buff_id);    

    //round robin assign remaining cores to tx cores 
    //reserve cores 0-1 for DPDK management and linux
    unsigned int buff_cores = 0; 
    for(int i=(tx_cores+2);i < tx_cores+2+max_buff_id;i++){
        
        //if we've hit buffer core limit, skip
        if ((core_map[i%tx_cores].total_fillers) > max_buff_fillers-1){
            continue;
        }

        core_map[i%tx_cores].filler_cores[core_map[i%tx_cores].total_fillers] = i;
        core_map[i%tx_cores].total_fillers++; 

        RTE_LOG(INFO, EAL, "Mapping buffer filler core %d to tx core %d\n", i, (i%tx_cores)+2);

        buff_cores++;
    }
    
    /* -------------------------- Initialize Mempools ---------------------------------------------------------------- */

    // Creates a new mempool in memory to hold the mbufs. */
    app_mempool = rte_pktmbuf_pool_create("PCAP_MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (app_mempool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    
    //create per tx core clone only mempools
    core_clone_mempools = calloc(tx_cores,sizeof(struct rte_mempool *));
    for (int i =0; i<tx_cores;i++){

        char name[32];
        sprintf(name,"tx_core_%d_mempool",i);

        core_clone_mempools[i] = rte_pktmbuf_pool_create(name, NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        
        //rte_pktmbuf_pool_create(name, NUM_CLONE_MBUFS,
        //CLONE_MBUF_CACHE_SIZE, 0, 0, rte_socket_id());

        if (core_clone_mempools[i] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %s\n",name);
    }


    /* -------------------------- Initialize all ports passed into the DPDK app ----------------------------------------- */

    uint16_t portid = 0;
    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("number of ports: %d\n", nb_ports);
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_dev_info dev_info;
        if (rte_eth_dev_info_get(portid, &dev_info) == 0){
            printf("port %u... %s\n", portid, dev_info.driver_name);
        }

        /* Initialize all ports. */
        if (ps_port_init(portid, app_mempool,tx_cores) != 0){
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
        }
    }

    /* -------------------------- Initialize global flowtable -------------------------------------------------------------- */
    //create a default action for the flow table
    struct ft_action default_action;
    default_action.kind = FT_ACT_NOP;
    default_action.default_rule = true;

    //populate the flowtable_config 
    struct ft_cfg flowtable_cfg;
    flowtable_cfg.default_action = &default_action;
    flowtable_cfg.name = "Global_Flowtable";
    flowtable_cfg.num_reader_threads = buff_cores;
    flowtable_cfg.qsbr_max_reclaim_size = 2048;
    flowtable_cfg.qsbr_reclaim_limit = 4096; 
    flowtable_cfg.shards = 1;
    flowtable_cfg.socket_id = rte_socket_id();
    flowtable_cfg.hash_algo = FT_HASH_CRC32;
    flowtable_cfg.entries = 1048576;

    //create the flowtable
    struct flow_table *global_ft = ft_create(&flowtable_cfg);
    if (global_ft == NULL){
        rte_exit(EXIT_FAILURE, "Failed to create flowtable\n");
    }

    /* -------------------------- Initialize all shared memory structures for pthreads & DPDK workers ---------------------- */

    //stats container 
    shared_app_stats = calloc(1, sizeof(struct psmith_stats_all));
    shared_app_stats->port_stats = calloc(1,sizeof(struct all_port_stats));
    shared_app_stats->buff_stats = calloc(1,sizeof(struct all_buff_worker_stats));
    shared_app_stats->tx_stats   = calloc(1,sizeof(struct all_tx_worker_stats));
    shared_app_stats->mem_stats  = calloc(1,sizeof(struct all_memory_stats));
    shared_app_stats->mem_stats->mstats = (struct mempool_stats*)calloc(tx_cores+1,sizeof(struct mempool_stats));

    //initialize per port stats 
    pthread_mutex_init(&shared_app_stats->port_stats->lock,NULL); 
    shared_app_stats->port_stats->num_ports = nb_ports;
    shared_app_stats->port_stats->per_port_stats = calloc(nb_ports, sizeof(struct single_port_stats));
    
    for(int i=0; i<nb_ports;i++){

        //figure out how many xstats are associaed with the port
        int n_xstats = rte_eth_xstats_get(i, NULL, 0);
        if (n_xstats < 0) {
            printf("Failed to get xstats count\n");
            return -1;
        }
        shared_app_stats->port_stats->per_port_stats[i].n_xstats = n_xstats;
        shared_app_stats->port_stats->per_port_stats[i].port_stats_names    = calloc(n_xstats, sizeof(struct rte_eth_xstat_name));
        shared_app_stats->port_stats->per_port_stats[i].prev_port_stats     = calloc(n_xstats, sizeof(struct rte_eth_xstat));
        shared_app_stats->port_stats->per_port_stats[i].current_port_stats  = calloc(n_xstats, sizeof(struct rte_eth_xstat));
        shared_app_stats->port_stats->per_port_stats[i].rates_port_stats    = calloc(n_xstats, sizeof(struct rte_eth_xstat));

        //preload xstat names array so we don't have to do it later 
        int ret = rte_eth_xstats_get_names(i, shared_app_stats->port_stats->per_port_stats[i].port_stats_names, n_xstats);
        if (ret < 0 || ret > n_xstats){
            rte_exit(EXIT_FAILURE, "Error: rte_eth_xstats_get_names() failed\n");
        }

        //initialize timestamps 
        clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->port_stats->per_port_stats[i].prev_ts);
        clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->port_stats->per_port_stats[i].curr_ts);
    }

    //initialize tx worker core stats 
    pthread_mutex_init(&shared_app_stats->tx_stats->lock,NULL);   
    shared_app_stats->tx_stats->num_workers = tx_cores;  
    shared_app_stats->tx_stats->prev_tx_worker_stats    = calloc(tx_cores, sizeof(struct single_tx_worker_stat_seq));
    shared_app_stats->tx_stats->current_tx_worker_stats = calloc(tx_cores, sizeof(struct single_tx_worker_stat_seq));
    shared_app_stats->tx_stats->rates_tx_worker_stats   = calloc(tx_cores, sizeof(struct single_tx_worker_stat_seq));
    //initialize timestamps 
    clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->tx_stats->prev_ts);
    clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->tx_stats->curr_ts);

    //initialize buffer worker core stats 
    pthread_mutex_init(&shared_app_stats->tx_stats->lock,NULL);   
    shared_app_stats->buff_stats->num_workers = buff_cores;  
    shared_app_stats->buff_stats->prev_buff_worker_stats    = calloc(tx_cores, sizeof(struct single_buff_worker_stat_seq));
    shared_app_stats->buff_stats->current_buff_worker_stats = calloc(tx_cores, sizeof(struct single_buff_worker_stat_seq));
    shared_app_stats->buff_stats->rates_buff_worker_stats   = calloc(tx_cores, sizeof(struct single_buff_worker_stat_seq));
    //initialize timestamps 
    clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->buff_stats->prev_ts);
    clock_gettime(CLOCK_MONOTONIC, &shared_app_stats->buff_stats->curr_ts);

    //shared app control memory 
    shared_app_state = calloc(1, sizeof(struct psmith_app_state));
    shared_app_state->tx_buff_core_mapping = core_map; 
    shared_app_state->mbuf_ts_off = mbuf_time_offset;
    shared_app_state->num_tx_cores = tx_cores;
    shared_app_state->num_buf_cores = buff_cores;
    shared_app_state->ports_configured = nb_ports;
    shared_app_state->port_status = calloc(nb_ports,sizeof(unsigned int));
    shared_app_state->port_enable = calloc(nb_ports,sizeof(unsigned int));
    shared_app_state->virt_channels_per_port = calloc(nb_ports,sizeof(unsigned int));
    shared_app_state->pcap_template_mpool = app_mempool;
    shared_app_state->txcore_clone_mpools = core_clone_mempools;
    shared_app_state->pcap_storage_t = calloc(1, sizeof(struct pcap_storage));
    shared_app_state->pcap_storage_t->slot_assignments = calloc(nb_ports,sizeof(int*));

    //init slot assignments for each port 
    for(int i=0; i<nb_ports;i++){
        shared_app_state->pcap_storage_t->slot_assignments[i] = calloc(tx_cores,sizeof(int));
        for (int j=0; j<tx_cores;j++){
            shared_app_state->pcap_storage_t->slot_assignments[i][j] = -1;
        }

        shared_app_state->virt_channels_per_port[i] = 1;
    }


    pthread_mutex_init(&shared_app_state->lock, NULL);

    //shared memory for pcap loading status
    struct pcap_loader_ctl *pcap_controller;
    pcap_controller = calloc(1, sizeof(struct pcap_loader_ctl));

    //shared memory for flowtable controller interface 
    struct ft_manager_ctl *ft_controller;
    ft_controller = calloc(1, sizeof(struct ft_manager_ctl));

    //create pthread args to pass shared resources 
    struct pthread_args *stats_args, *control_args, *pcap_loader_args, *ft_manager_args; 

    stats_args = calloc(1,sizeof(struct pthread_args));
    stats_args->global_stats = shared_app_stats;
    stats_args->global_state = shared_app_state;
    stats_args->global_flowtable = global_ft; 
    stats_args->pcap_controller = pcap_controller;
    stats_args->ft_controller = ft_controller;
    stats_args->private_args = (void *)&stats_poll_rate_ms; 

    control_args = calloc(1,sizeof(struct pthread_args));
    control_args->global_stats = shared_app_stats;
    control_args->global_state = shared_app_state;
    control_args->global_flowtable = global_ft;
    control_args->pcap_controller = pcap_controller;
    control_args->ft_controller = ft_controller;
    control_args->private_args = (void *)&ctl_port;

    pcap_loader_args = calloc(1,sizeof(struct pthread_args));
    pcap_loader_args->global_stats = shared_app_stats;
    pcap_loader_args->global_state = shared_app_state;
    pcap_loader_args->global_flowtable = global_ft;
    pcap_loader_args->pcap_controller = pcap_controller;    
    pcap_loader_args->ft_controller = ft_controller;

    ft_manager_args = calloc(1,sizeof(struct pthread_args));
    ft_manager_args->global_stats = shared_app_stats;
    ft_manager_args->global_state = shared_app_state;
    ft_manager_args->global_flowtable = global_ft;
    ft_manager_args->pcap_controller = pcap_controller;   
    ft_manager_args->ft_controller = ft_controller; 
    
    /* -------------------------- Create shared memory structures for Buffer Filler to Tx Core Packet Transmission ------------------------------*/

    //create and init all rx rings used to communicate between buffer and tx cores 
    struct rte_ring *rx_tx_rings[tx_cores][nb_ports][buffs_per_core];

    for (int i=0; i<tx_cores;i++){
        for (int j=0; j<nb_ports;j++){
            for(int k=0;k<buffs_per_core;k++){
                //for each port + buffer combo, create a rte_ring, and assign it to the buffer core 
                char name[32]; 
                int n = snprintf(name,sizeof(name),"txc_%d_pid_%d_bc_%d_r",i,j,k);
                if (n < 0 || n >= (int)sizeof(name)) rte_exit(EXIT_FAILURE, "name too long\n");

                printf("ringname: %s\n",name);
                struct rte_ring *r = rte_ring_create(name,RXTX_RING_SIZE,rte_socket_id(),RING_F_SC_DEQ);   // single-consumer fast path
                if (!r) 
                    rte_panic("ring create failed\n");

                rx_tx_rings[i][j][k] = r;
            }
        }
    }

    
    // create tx and buffer filler cores 
    //filler cores are indexed through the tx core they are assigned to 
    struct tx_worker_args *tx_args_array = (struct tx_worker_args *)calloc(tx_cores,sizeof(struct tx_worker_args));
    struct buff_worker_args *buff_args_array = (struct buff_worker_args *)calloc(buff_cores,sizeof(struct buff_worker_args));
    int buf_ctr = 0;

    for(int i=0; i<tx_cores;i++){
        tx_args_array[i].global_state = shared_app_state;
        tx_args_array[i].global_stats = shared_app_stats;
        tx_args_array[i].num_buffer_rings = calloc(nb_ports,sizeof(unsigned int));
        tx_args_array[i].clone_mpool  = core_clone_mempools[i];
        tx_args_array[i].num_ports = nb_ports;
        tx_args_array[i].tx_thread_index = i;
        tx_args_array[i].core_map = core_map;
        tx_args_array[i].global_flowtable = global_ft;

        //give tx core a pointer to all of its rx rings 
        tx_args_array[i].buffer_rings = (struct rte_ring ***)calloc(nb_ports,sizeof(struct rte_ring **));
        for (int l =0;l<nb_ports;l++){
            tx_args_array[i].buffer_rings[l] = (struct rte_ring **)calloc(buffs_per_core, sizeof(struct rte_ring*));
            tx_args_array[i].num_buffer_rings[l] = buffs_per_core;
            
            for(int m =0;m<buffs_per_core;m++){
                tx_args_array[i].buffer_rings[l][m] = rx_tx_rings[i][l][m];
            }
        }


        //for each buffer filler linked to this tx core 
        for (int j=0; j < core_map[i].total_fillers; j++){
            buff_args_array[buf_ctr].buff_thread_index      = buf_ctr;
            buff_args_array[buf_ctr].global_state           = shared_app_state;
            buff_args_array[buf_ctr].global_stats           = shared_app_stats; 
            buff_args_array[buf_ctr].clone_mpool            = core_clone_mempools[i];
            buff_args_array[buf_ctr].linked_tx_core         = i;
            buff_args_array[buf_ctr].num_ports              = nb_ports;
            buff_args_array[buf_ctr].global_flowtable       = global_ft;

            //setup parameters for dynamic expansion mode 
            buff_args_array[buf_ctr].virt_ip_cnt            = 65536;
            buff_args_array[buf_ctr].tsc_hz                 = tsc_hz;
            buff_args_array[buf_ctr].virtual_flows          = calloc(nb_ports,sizeof(struct virtual_flow *));

            //allocate space for buffer_rings
            buff_args_array[buf_ctr].buffer_rings           = (struct rte_ring **)calloc(nb_ports,sizeof(struct rte_ring*));

            //for each configured port
            for (int k = 0; k < nb_ports; k++){           
                buff_args_array[buf_ctr].buffer_rings[k] = rx_tx_rings[i][k][j]; //assign this buffer threads unique port + ring index

                //make sure each virtual flow knows its index
                buff_args_array[buf_ctr].virtual_flows[k] = calloc(65536,sizeof(struct virtual_flow));
                for(int l=0;l < buff_args_array[buf_ctr].virt_ip_cnt; l++){
                    buff_args_array[buf_ctr].virtual_flows[k][l].vert_flow_index = l; 
                }
            }

            buf_ctr++;
        }

    }

    /* -------------------------- Launch DPDK Worker Cores -------------------------------------------- */

    // Launch DPDK tx workers with tx args
    for(int i=2;i<tx_cores+2;i++){
        rte_eal_remote_launch(tx_worker, &tx_args_array[i-2], i);
    }

    // Launch DPDK buffer filler workers with buff args 
    buf_ctr = 0;
    for(int i=0;i<tx_cores;i++){
        for (int j=0; j< core_map[i].total_fillers;j++){
            rte_eal_remote_launch(buffer_worker, &buff_args_array[buf_ctr], core_map[i].filler_cores[j]);
            buf_ctr++;
        }
    }
    
    /* -------------------------- Launch sevice pthreads that run on the main core ---------------------- */

    //Configure and Launch support pthreads on main core 
    //pin pthreads to main core 
    CPU_ZERO(&cpuset);
    CPU_SET(main_lcore_id, &cpuset);

    //launch and bind control server thread 
    if (pthread_create(&controller_thread, NULL, run_control_server,control_args) != 0){
        rte_exit(EXIT_FAILURE, "Control thread creation failed\n");
    }

    //launch and bind stats collector thread 
    if (pthread_create(&stats_thread, NULL, run_stats_thread,stats_args) != 0){
        rte_exit(EXIT_FAILURE, "stats thread creation failed\n");
    }

    //launch and bind pcap loader thread 
    if (pthread_create(&pcap_loader_thread, NULL, run_pcap_loader_thread,pcap_loader_args) != 0){
        rte_exit(EXIT_FAILURE, "pcap loader thread creation failed\n");
    }

    //launch and bind ft_manager thread 
    if (pthread_create(&ft_manager_thread, NULL, run_ft_manager_thread,ft_manager_args) != 0){
        rte_exit(EXIT_FAILURE, "flowtable manager thread creation failed\n");
    }

    //make sure support threads only run on main CPU, don't want them bothering DPDK tx / buffer threads
    pthread_setaffinity_np(controller_thread, sizeof(cpu_set_t), &cpuset);
    pthread_setaffinity_np(stats_thread, sizeof(cpu_set_t), &cpuset);
    pthread_setaffinity_np(pcap_loader_thread, sizeof(cpu_set_t), &cpuset);
    pthread_setaffinity_np(ft_manager_thread, sizeof(cpu_set_t), &cpuset);
    
    /* -------------------------- Mark app as initialized, end of init thread until exit ------------------ */

    //mark app as initialized 
    pthread_mutex_lock(&shared_app_state->lock);
    shared_app_state->app_initialized = true;
    pthread_mutex_unlock(&shared_app_state->lock);

    //wait and clean up
    rte_eal_mp_wait_lcore();
    pthread_join(controller_thread, NULL);
    pthread_join(stats_thread, NULL);
    pthread_join(pcap_loader_thread, NULL);
    pthread_join(ft_manager_thread, NULL);
    printf("Application exiting cleanly");
    return 0;
}
