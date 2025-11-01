/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: tx_worker.c 
Description: Primary entry point and supporting code for DPDK transmit core threads. Transmit cores are responsible for 
taking pcap data provided by buffer fill threads and transmitting them out the approperate network port. Multiple Tx cores can 
drive traffic out the same network port (each tx core has a separate tx queue to each configured network port), however order 
across different tx cores is not maintained. To maintain per flow order, tx workers read data provided by their linked buffer threads using a 
per tx core + port global sequence ID. 

Tx cores are not signaled to start / stop, data flow is controlled by the buffer threads. Tx cores simply monitor their assigned shared memory 
double buffer arrays for valid data to transmit. 

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <limits.h>
#include <rte_ring.h>

#include "control.h"
#include "app_defines.h"
#include "ports.h"
#include "stats.h"
#include "tx_worker.h"
#include "buff_worker.h"

/* Main entry point for tx worker thread */
int tx_worker(__rte_unused void *arg) {

    //parse tx args struct for future use 
    struct tx_worker_args *tx_args = (struct tx_worker_args *)arg;
    struct rte_mbuf *rx_burst[RING_BURST];

    //figure out which core i'm running on 
    unsigned lcore_id = rte_lcore_id();

    //Figure out which buffer threads map to me and what the double buffer struct ID's are 
    printf("\n--------------------- Tx Lcore %d --------------------------\n", lcore_id);
    printf("Lcore_%d - Starting Transmit Thread\n", lcore_id);
    printf("Lcore_%d - Number of Configured Ports: %d\n",lcore_id,tx_args->num_ports);
    /* Main tx thread loop */
    for(;;){
        //iterate over each port, there is one buffer pair per port 
        for(int i=0; i< tx_args->num_ports; i++){
        
            //for each port, there can be one or more buffer fillers sending data, check each one for data
            for (int j=0; j< tx_args->num_buffer_rings[i]; j++){
                    uint32_t spins = 0;
                    uint16_t tx_n,rx_n = 0;
                    uint16_t sent = 0;

                    //dequeue up to RX_BURST number of packets
                    rx_n = rte_ring_sc_dequeue_burst(tx_args->buffer_rings[i][j], (void **)rx_burst, RING_BURST, NULL);
                    if (rx_n == 0) {
                        // empty: avoid hot spinning
                        rte_pause();
                        continue;
                    }

                    //transmit what we've dequeued
                    while(sent < rx_n){
                        tx_n = rte_eth_tx_burst(i,tx_args->tx_thread_index,rx_burst+sent,rx_n-sent);

                        //if we couldn't send anything 
                        if(tx_n == 0){
                            
                            //periodically call exth_tx_done_cleanup to free up any mbufs that are eligable for recycling. Note normally all mbuff's successfully
                            //sent via rte_eth_tx_burst are recycled by the PMD driver, this is more for corner cases. 
                            if ((++spins & 0x3F) == 0)
                                rte_eth_tx_done_cleanup(i, tx_args->tx_thread_index, 0); // 0 = clean as much as possible

                            rte_pause();
                        }
                        sent +=tx_n; 
                    }
                }
            }
        }
    return 0;
}

