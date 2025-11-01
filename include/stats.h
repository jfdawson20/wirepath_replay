/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: stats.h 
Description: header file stats structs and stats thread declarations

*/

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdatomic.h> 
#include <pthread.h>
#include <time.h> 
#include <rte_common.h>


void *run_stats_thread(void *arg);

/* per worker or per port stat structs */
struct single_tx_worker_stat_seq {
    atomic_uint     seq; 
    unsigned int    coreid;
    uint64_t        tx_packets;
    uint64_t        tx_bytes; 
    uint64_t        tx_drops;
}__rte_cache_aligned; 


struct single_buff_worker_stat_seq {
    atomic_uint     seq; 
    unsigned int    coreid;
    uint64_t        tx_packets;
    uint64_t        tx_bytes; 
}__rte_cache_aligned; 

struct single_port_stats {
    int n_xstats;
    struct rte_eth_xstat_name   *port_stats_names;               
    struct rte_eth_xstat        *prev_port_stats;
    struct rte_eth_xstat        *current_port_stats; 
    struct rte_eth_xstat        *rates_port_stats;     
    struct timespec prev_ts; 
    struct timespec curr_ts; 
};

/* structs to aggregate groups of workers or port stats */
// struct that contains arrays of tx worker stats and rates 
struct all_tx_worker_stats {
    pthread_mutex_t lock;
    unsigned int num_workers; 
    struct single_tx_worker_stat_seq  *prev_tx_worker_stats;
    struct single_tx_worker_stat_seq  *current_tx_worker_stats;
    struct single_tx_worker_stat_seq  *rates_tx_worker_stats;
    struct timespec prev_ts; 
    struct timespec curr_ts; 
};

//struct that contains arrays of buffer filler stats and rate
struct all_buff_worker_stats {
    pthread_mutex_t lock; 
    unsigned int num_workers;
    struct single_buff_worker_stat_seq  *prev_buff_worker_stats;
    struct single_buff_worker_stat_seq  *current_buff_worker_stats;
    struct single_buff_worker_stat_seq  *rates_buff_worker_stats;
    struct timespec prev_ts; 
    struct timespec curr_ts; 
};

//struct that contains array of port stat structs
struct all_port_stats {
    pthread_mutex_t lock; 
    unsigned int num_ports; 
    struct single_port_stats *per_port_stats; 
};


//memory subsystem stats 
struct mempool_stats{
    uint64_t available; 
    uint64_t used; 
    uint64_t total; 
};

struct all_memory_stats {
    pthread_mutex_t lock; 
    struct mempool_stats * mstats;
};


//main stats entry struct 
struct psmith_stats_all {
    struct all_port_stats           *port_stats;
    struct all_tx_worker_stats      *tx_stats;
    struct all_buff_worker_stats    *buff_stats;
    struct all_memory_stats         *mem_stats; 
};


#endif