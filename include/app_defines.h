/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: app_defines.h
Description: header file containing app wide constants and structs

*/

#ifndef APP_DEFINE_H
#define APP_DEFINE_H
#include <rte_log.h>
#include <stats.h> 
#include <control.h> 
#include <rte_mempool.h>

#include "pcap_loader.h"
#include "flowtable.h"
#include "ft_manager.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

//pcap mbuf 
#define NUM_MBUFS 1000000
#define MBUF_CACHE_SIZE 256
#define PCAP_READ_CHUNK 256

//per core clone mbuffs
#define NUM_CLONE_MBUFS 8192
#define CLONE_MBUF_CACHE_SIZE 256

//interconnect ring properties
#define RING_BURST 128
#define RXTX_RING_SIZE (1u << 14) 

//struct for passing shared memory and arguments to pthreads (for control and stats threads)
struct pthread_args {
    struct psmith_stats_all  *global_stats; 
    struct psmith_app_state  *global_state;
    struct flow_table        *global_flowtable;  
    struct pcap_loader_ctl   *pcap_controller;
    struct ft_manager_ctl    *ft_controller;

    void *private_args; 
};

//structs for passing shared memory and arguments to DPDK lcores
struct tx_worker_args {
    unsigned int             tx_thread_index;
    struct psmith_stats_all  *global_stats; 
    struct psmith_app_state  *global_state;  
    struct flow_table        *global_flowtable;  
    struct rte_mempool       *clone_mpool;
    unsigned int             num_ports;         //how many ports are configured?
    unsigned int             *num_buffer_rings; //array, how many input rings per port? 
    struct rte_ring          ***buffer_rings;    
    struct core_mapping      *core_map;
};

struct buff_worker_args {
    unsigned int             buff_thread_index; //index starting at 0 to id the thread
    struct psmith_stats_all  *global_stats; 
    struct psmith_app_state  *global_state;  
    struct flow_table        *global_flowtable;  
    struct pcap_loader_ctl   *pcap_controller;
    struct rte_mempool       *clone_mpool;
    unsigned int             linked_tx_core;
    unsigned int             num_ports;
    struct rte_ring          **buffer_rings;    //buffer workers just have a list of rings, 1x ring per configured port,

    //parameters for handling virtual flow generation 
    uint64_t tsc_hz; 
    uint32_t vert_ip_offset;
    uint32_t virt_ip_cnt;
    struct virtual_flow    **virtual_flows; //array of virt flow pointers, 1x array per port
};

struct core_mapping {
    unsigned int tx_core; 
    unsigned int *filler_cores;
    unsigned int total_fillers;
};

#endif 