/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: stats.c 
Description: contains the main entry point for the stats monitoring thread. The stats monitor is a pthread launched from the main DPDK 
core and is responsible for periodically collecting, processing, and publishing statistics about the application. The initial monitoring tasks 
includes memory, port stats, flow table, load balancer, etc. aggregation. but is the landing place for any "i need to monitor X stats" functionality.

The main thread runs in a infinite loop at a poll frequency specified at launch time. 
*/

#define _GNU_SOURCE

#include <rte_ethdev.h> 
#include <rte_mempool.h>
#include <time.h>
#include <stdio.h> 
#include <unistd.h>

#include "ppr_stats.h"
#include "ppr_app_defines.h"
#include "ppr_time.h"
#include "ppr_log.h"
#include "ppr_ports.h"

/* function for calculating time differences of timespec structs*/
static double timespec_diff_sec(struct timespec *a, struct timespec *b) {
    return (b->tv_sec - a->tv_sec) +
           (b->tv_nsec - a->tv_nsec) / 1e9;
}

static inline uint64_t safe_diff_u64(uint64_t cur, uint64_t prev)
{
    if (cur >= prev) {
        return cur - prev;
    } else {
        return 0;
    }
}


/* Collect memory statistics for all configured memory pools used by the application and update shared 
   stats memory structures 
*/
static int update_memstats(ppr_thread_args_t *thread_args){
    (void)thread_args;
    //ppr_stats_all_t *stats_memory = thread_args->global_stats;

    
    return 0;
}

/* Collect port statistics and compute rates. Function gathers DPDK xstats and computes the rate for each statistic based on the poll frequency */
static int update_portstats(ppr_thread_args_t *thread_args){
    ppr_ports_t *global_port_list = thread_args->global_port_list;

    int rc =0;
    for (unsigned int i =0; i < global_port_list->num_ports; i++){
        if(!global_port_list->ports[i].name){
            PPR_LOG(PPR_LOG_STATS, RTE_LOG_ERR, "Port name is NULL for port index %u\n", i);
            continue;
        }

        ppr_port_entry_t *port_entry = &global_port_list->ports[i];
        if(!port_entry){
            PPR_LOG(PPR_LOG_STATS, RTE_LOG_ERR, "Port entry is NULL for port index %u\n", i);
            continue;
        }

        if(port_entry->kind == PPR_PORT_TYPE_DROP){
            continue;
        }
        //lock mutex 
        pthread_mutex_lock(&port_entry->stats.lock);
        //capture current time
        clock_gettime(CLOCK_MONOTONIC, &port_entry->stats.curr_ts);

        //calculate time delta 
        double time_delta = timespec_diff_sec(&port_entry->stats.prev_ts,&port_entry->stats.curr_ts);  

        //update stats for this port
        if (port_entry->kind == PPR_PORT_TYPE_RING){
            //not used in this app
            continue;
        }
        else{ 
            //fetch port stats
            int ret = rte_eth_xstats_get(port_entry->port_id,port_entry->stats.xstats.current_port_stats, port_entry->stats.xstats.n_xstats);
            if (ret < 0 || ret > port_entry->stats.xstats.n_xstats){
                //unlock 
                pthread_mutex_unlock(&port_entry->stats.lock);
                return -1;
            }

            //compute rates 
            for (int j=0; j<port_entry->stats.xstats.n_xstats; j++){
                uint64_t diff_value = 0;
                //handle cases where counters have wrapped, calculate diff
                if(port_entry->stats.xstats.current_port_stats[j].value >= port_entry->stats.xstats.prev_port_stats[j].value){
                    diff_value = port_entry->stats.xstats.current_port_stats[j].value - port_entry->stats.xstats.prev_port_stats[j].value;
                } else {
                    diff_value = (UINT64_MAX - port_entry->stats.xstats.prev_port_stats[j].value) + port_entry->stats.xstats.current_port_stats[j].value + 1;
                }

                double rate = (double)diff_value / time_delta; 
                
                //update rate array
               port_entry->stats.xstats.rates_port_stats[j].id = port_entry->stats.xstats.current_port_stats[j].id;
               port_entry->stats.xstats.rates_port_stats[j].value = (uint64_t)rate;

               //update the prev value array
               port_entry->stats.xstats.prev_port_stats[j].value = port_entry->stats.xstats.current_port_stats[j].value;

            }            
        }

        //update prev ts 
        port_entry->stats.prev_ts = port_entry->stats.curr_ts;

        //unlock mutex
        pthread_mutex_unlock(&port_entry->stats.lock);
    }
    
    return 0;
}

static int ppr_update_worker_stats(ppr_thread_args_t *thread_args){
    ppr_stats_all_t *stats_memory = thread_args->global_stats;
    
    /* update and process port stats */
    pthread_mutex_lock(&stats_memory->worker_stats->lock);

    //get total worker core count
    unsigned int num_workers = thread_args->global_stats->worker_stats->num_workers;

    //capture current time
    clock_gettime(CLOCK_MONOTONIC, &stats_memory->worker_stats->curr_ts); 
    
    ppr_single_worker_stat_seq_t *current;
    for(unsigned int i =0; i< num_workers; i++){
        //get current stats 
        current = &stats_memory->worker_stats->current_worker_stats[i];
        //calculate time delta
        double time_delta = timespec_diff_sec(&stats_memory->worker_stats->prev_ts,&stats_memory->worker_stats->curr_ts);

        //compute rates
        ppr_single_worker_stat_seq_t *rates = &stats_memory->worker_stats->rates_worker_stats[i];

        uint64_t diff_rx_pkts           = safe_diff_u64(current->rx_packets,         stats_memory->worker_stats->prev_worker_stats[i].rx_packets);
        uint64_t diff_rx_bytes          = safe_diff_u64(current->rx_bytes,           stats_memory->worker_stats->prev_worker_stats[i].rx_bytes);
        uint64_t diff_rx_bad_pkts       = safe_diff_u64(current->rx_bad_packets,     stats_memory->worker_stats->prev_worker_stats[i].rx_bad_packets);
        uint64_t diff_frag_rx           = safe_diff_u64(current->frag_packets_rx, stats_memory->worker_stats->prev_worker_stats[i].frag_packets_rx);
        uint64_t diff_frag_reassembled  = safe_diff_u64(current->frag_reassembled_packets, stats_memory->worker_stats->prev_worker_stats[i].frag_reassembled_packets);
        uint64_t diff_tx_pkts           = safe_diff_u64(current->tx_packets,         stats_memory->worker_stats->prev_worker_stats[i].tx_packets);
        uint64_t diff_tx_bytes          = safe_diff_u64(current->tx_bytes,           stats_memory->worker_stats->prev_worker_stats[i].tx_bytes);
        uint64_t diff_tx_dropped        = safe_diff_u64(current->tx_dropped_packets, stats_memory->worker_stats->prev_worker_stats[i].tx_dropped_packets);

        rates->rx_packets                 = (uint64_t)((double)diff_rx_pkts    / time_delta);
        rates->rx_bytes                   = (uint64_t)((double)diff_rx_bytes   / time_delta);
        rates->rx_bad_packets             = (uint64_t)((double)diff_rx_bad_pkts/ time_delta);
        rates->frag_packets_rx            = (uint64_t)((double)diff_frag_rx   / time_delta);
        rates->frag_reassembled_packets   = (uint64_t)((double)diff_frag_reassembled / time_delta);
        rates->tx_packets                 = (uint64_t)((double)diff_tx_pkts    / time_delta);
        rates->tx_bytes                   = (uint64_t)((double)diff_tx_bytes   / time_delta);
        rates->tx_dropped_packets         = (uint64_t)((double)diff_tx_dropped / time_delta);

        //update prev stats
        stats_memory->worker_stats->prev_worker_stats[i].rx_packets               = current->rx_packets;
        stats_memory->worker_stats->prev_worker_stats[i].rx_bytes                 = current->rx_bytes;
        stats_memory->worker_stats->prev_worker_stats[i].rx_bad_packets           = current->rx_bad_packets;
        stats_memory->worker_stats->prev_worker_stats[i].frag_packets_rx          = current->frag_packets_rx;
        stats_memory->worker_stats->prev_worker_stats[i].frag_reassembled_packets = current->frag_reassembled_packets;
        stats_memory->worker_stats->prev_worker_stats[i].tx_packets               = current->tx_packets;
        stats_memory->worker_stats->prev_worker_stats[i].tx_bytes                 = current->tx_bytes;
        stats_memory->worker_stats->prev_worker_stats[i].tx_dropped_packets       = current->tx_dropped_packets;


    }

    //update prev ts    
    stats_memory->worker_stats->prev_ts = stats_memory->worker_stats->curr_ts;
    /* update and process port stats */
    pthread_mutex_unlock(&stats_memory->worker_stats->lock);
    return 0;
}


/* Main stats monitoring and publishing thread */
void *run_ppr_stats_thread(void *arg) {
    //parse thread args 
    ppr_thread_args_t *thread_args  = (ppr_thread_args_t *)arg;   
    ppr_ports_t *global_port_list = thread_args->global_port_list;
    int rc = 0; 

    //setup poll rate variables
    const uint64_t hz = rte_get_timer_hz();
    uint64_t t0 = rte_get_timer_cycles();
    uint64_t next_tick = t0;
    const uint64_t period = hz * thread_args->poll_period_ms / 1000ULL;   
    
    //mark thread ready
    atomic_store_explicit(&thread_args->thread_ready, true, memory_order_relaxed);    

    //wait for app ready flag from main thread
    while (atomic_load_explicit(thread_args->app_ready, memory_order_relaxed) == false) {
        rte_pause();
    }


    //main poll loop 
    while(!force_quit) {
        //only run perodically 
        uint64_t t1 = rte_get_timer_cycles();
        if ((int64_t)(t1 - next_tick) >= 0) {
            next_tick += period;
            //1) update network stats, reads xstats for each active port
            update_portstats(thread_args);

            //2) update memory stats
            update_memstats(thread_args);

            //3) update worker stats 
            ppr_update_worker_stats(thread_args);

            //4) update ACL stats 
            ppr_acl_stats_accumulator(thread_args->acl_runtime);
        }

        // Not time yet: compute remaining time and sleep
        uint64_t remain_cycles = next_tick - t1;
        double remain_sec = (double)remain_cycles / (double)hz;
        uint64_t remain_ns = (uint64_t)(remain_sec * 1e9);

        if (remain_ns > MIN_SLEEP_NS) {
            struct timespec ts;
            ts.tv_sec  = remain_ns / 1000000000ULL;
            ts.tv_nsec = remain_ns % 1000000000ULL;
            nanosleep(&ts, NULL);
        } else {
            // very short wait: cheap hint
            sched_yield();   // or rte_pause() if this is on an isolated core
        }
    
    }

    PPR_LOG(PPR_LOG_STATS, RTE_LOG_INFO, "\n\tStats Thread - Thread Exiting\n");
    return (void*)0;
}