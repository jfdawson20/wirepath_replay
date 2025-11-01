/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: stats.c 
Description: contains the main entry point for the stats monitoring thread. The stats monitor is a pthread launched from the main DPDK 
core and is responsible for periodically collecting, processing, and publishing statistics about the application. The initial monitoring tasks 
includes memory and port stats aggregation, but this will be extended in the future to include per worker core statistics as well as other system 
resource metrics. 

The main thread runs in a infinite loop at a poll frequency specified at launch time. 
*/

#include <rte_ethdev.h> 
#include <rte_mempool.h>
#include <time.h>
#include <stdio.h> 
#include <unistd.h>

#include "stats.h"
#include "app_defines.h"

/* function for calculating time differences of timespec structs*/
double timespec_diff_sec(struct timespec *a, struct timespec *b) {
    return (b->tv_sec - a->tv_sec) +
           (b->tv_nsec - a->tv_nsec) / 1e9;
}

/* Collect memory statistics for all configured memory pools used by the application and update shared 
   stats memory structures 
*/
static int update_memstats(struct pthread_args *thread_args){
    struct psmith_stats_all *stats_memory = thread_args->global_stats;
    struct rte_mempool *mp = thread_args->global_state->pcap_template_mpool;
    
    pthread_mutex_lock(&stats_memory->mem_stats->lock);
    //template memory
    stats_memory->mem_stats->mstats[0].available  = rte_mempool_avail_count(mp);
    stats_memory->mem_stats->mstats[0].used       = rte_mempool_in_use_count(mp);
    stats_memory->mem_stats->mstats[0].total      = stats_memory->mem_stats->mstats[0].available +  stats_memory->mem_stats->mstats[0].used;

    //per tx core clone memory
    for (int i=0; i<thread_args->global_state->num_tx_cores;i++){
        struct rte_mempool *mp = thread_args->global_state->txcore_clone_mpools[i];
        stats_memory->mem_stats->mstats[i+1].available  = rte_mempool_avail_count(mp);
        stats_memory->mem_stats->mstats[i+1].used       = rte_mempool_in_use_count(mp);
        stats_memory->mem_stats->mstats[i+1].total      = stats_memory->mem_stats->mstats[i+1].available +  stats_memory->mem_stats->mstats[i+1].used;        
    }

    pthread_mutex_unlock(&stats_memory->mem_stats->lock);
    
    return 0;
}

/* Collect port statistics and compute rates. Function gathers DPDK xstats and computes the rate for each statistic based on the poll frequency */
static int update_portstats(struct pthread_args *thread_args){
    struct psmith_stats_all *stats_memory = thread_args->global_stats;

    /* update and process port stats */
    pthread_mutex_lock(&stats_memory->port_stats->lock);
    for(int i=0; i<stats_memory->port_stats->num_ports; i++ ){

        //capture current time
        clock_gettime(CLOCK_MONOTONIC, &stats_memory->port_stats->per_port_stats[i].curr_ts);

        //fetch port stats 
        int ret = rte_eth_xstats_get(i,stats_memory->port_stats->per_port_stats[i].current_port_stats, stats_memory->port_stats->per_port_stats[i].n_xstats);
        if (ret < 0 || ret > stats_memory->port_stats->per_port_stats->n_xstats){
            rte_exit(EXIT_FAILURE, "Error: rte_eth_xstats_get_names() failed\n");
        }

        //calculate time delta 
        double time_delta = timespec_diff_sec(&stats_memory->port_stats->per_port_stats[i].prev_ts,&stats_memory->port_stats->per_port_stats[i].curr_ts);
        //compute rates 
        for (int j=0; j<stats_memory->port_stats->per_port_stats[i].n_xstats; j++){
            uint64_t diff_value = 0; 
            //handle cases where counters have wrapped, calculate diff 
            if(stats_memory->port_stats->per_port_stats[i].current_port_stats[j].value >= stats_memory->port_stats->per_port_stats[i].prev_port_stats[j].value){
                diff_value = stats_memory->port_stats->per_port_stats[i].current_port_stats[j].value - stats_memory->port_stats->per_port_stats[i].prev_port_stats[j].value;
            } else {
                printf("rolling\n");
                diff_value = (UINT64_MAX - stats_memory->port_stats->per_port_stats[i].prev_port_stats[j].value) + stats_memory->port_stats->per_port_stats[i].current_port_stats[j].value+ 1;
            }

            double rate = (double)diff_value / time_delta; 
            
            //update rate array
            stats_memory->port_stats->per_port_stats[i].rates_port_stats[j].id = stats_memory->port_stats->per_port_stats[i].current_port_stats[j].id;
            stats_memory->port_stats->per_port_stats[i].rates_port_stats[j].value = (uint64_t)rate;

            /*
            if (strcmp(stats_memory->port_stats->per_port_stats[i].port_stats_names[j].name,"tx_good_bytes") == 0){
                printf("name: %s\n", stats_memory->port_stats->per_port_stats[i].port_stats_names[j].name);
                printf("previous: %ld\n", stats_memory->port_stats->per_port_stats[i].prev_port_stats[j].value);
                printf("current: %ld\n", stats_memory->port_stats->per_port_stats[i].current_port_stats[j].value);
                printf("rate: %ld\n\n", stats_memory->port_stats->per_port_stats[i].rates_port_stats[j].value);
            }
            */
           
            //update the prev value array
            stats_memory->port_stats->per_port_stats[i].prev_port_stats[j].value = stats_memory->port_stats->per_port_stats[i].current_port_stats[j].value;

        }
        

        //update prev ts 
        stats_memory->port_stats->per_port_stats[i].prev_ts = stats_memory->port_stats->per_port_stats[i].curr_ts;

        }
        //release port stats lock 
        pthread_mutex_unlock(&stats_memory->port_stats->lock);
    return 0;
}

/* Main stats monitoring and publishing thread */
void *run_stats_thread(void *arg) {
    //parse thread args 
    struct pthread_args *thread_args  = (struct pthread_args *)arg;

    unsigned int poll_wait_ms = *(unsigned int*)thread_args->private_args;     

    //main poll loop 
    while (1) {

        //update network stats, reads xstats for each active port
        update_portstats(thread_args);

        //update memory stats 
        update_memstats(thread_args);

        //update tx worker stats (TODO)

        //update buffer worker stats (TODO)

        //sleep for poll time
        usleep(poll_wait_ms * 1000);    
    }
}