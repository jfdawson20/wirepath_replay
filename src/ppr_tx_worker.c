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
#include <sched.h>

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

#include "ppr_control.h"
#include "ppr_app_defines.h"
#include "ppr_ports.h"
#include "ppr_stats.h"
#include "ppr_tx_worker.h"
#include "ppr_buff_worker.h"
#include "ppr_mbuf_fields.h"
#include "ppr_time.h"


static inline uint16_t build_tx_burst(struct rte_mbuf **tx_pkts,
               uint16_t max_pkts,
               pcap_storage_t *pcap_storage,
               uint32_t slot_id, 
               int mbuf_ts_off,
               struct rte_mempool *tx_pool,
               ppr_port_stream_ctx_t *psc,
               ppr_vc_ctx_t *vc,
               uint64_t phase) 
{
    uint16_t nb = 0;

    if (slot_id == UINT32_MAX)
        return 0;

    pcap_mbuff_slot_t *slot =
        atomic_load_explicit(&pcap_storage->slots[slot_id], memory_order_acquire);
    if (!slot || !slot->mbuf_array || !slot->mbuf_array->pkts)
        return 0;

    while (nb < max_pkts && vc->pcap_idx < slot->numpackets) {
        struct rte_mbuf *tmpl = slot->mbuf_array->pkts[vc->pcap_idx];
        if (!tmpl) break;

        if (psc->pace_mode == VC_PACE_PCAP_TS) {
            uint64_t rel_ts = my_ts_get(tmpl, mbuf_ts_off);
            if (unlikely(rel_ts < vc->base_rel_ns)) {
                break; // end VC for this epoch
            }
            uint64_t rel = rel_ts - vc->base_rel_ns;  
            uint64_t pkt_phase = (vc->start_offset_ns + rel) % psc->replay_window_ns;
            if (pkt_phase > phase) 
                break; // not time yet

        }

        // clone template (shares data), good enough for skeleton
        struct rte_mbuf *c = rte_pktmbuf_copy(tmpl, tx_pool,0,UINT32_MAX);
        if (unlikely(c == NULL)) {
            printf("failed to copy\n");
            break; // pool pressure: just send the ones we cloned
        }

        tx_pkts[nb++] = c;
        vc->pcap_idx++;
    }
    return nb;
}


/* Main entry point for tx worker thread */
int run_tx_worker(__rte_unused void *arg) { 

    //parse tx args struct for future use 
    ppr_thread_args_t               *thread_args = (ppr_thread_args_t *)arg;
    ppr_ports_t                     *global_port_list = thread_args->global_port_list;
    ppr_tx_worker_ctx_t             *tx_worker_ctx = thread_args->tx_worker_ctx; 
    struct rte_mempool              *tx_pool = tx_worker_ctx->tx_pool;
    uint16_t                        mbuf_ts_off = thread_args->mbuf_ts_off; 
    //int                             rc = 0;     

    //tx buffer 
    struct rte_mbuf *tx_pkts[BURST_SIZE_MAX];

    //num ports this tx worker services
    uint16_t num_ports = tx_worker_ctx->num_ports;

    //mark thread ready
    atomic_store_explicit(&thread_args->thread_ready, true, memory_order_relaxed);

    //wait for app ready flag from main thread
    while (atomic_load_explicit(thread_args->app_ready, memory_order_relaxed) == false) {
        rte_pause();
    }

    int cpu = sched_getcpu();
    PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO, "dp_worker_main started: lcore=%u linux_cpu=%d index=%u\n", rte_lcore_id(), cpu, thread_args->thread_index);

    /* Main tx thread loop */
    while(!force_quit){

        //get current timestamp counter, this is the current time in ns since some arbitrary point in the past
        //when we first start transmitting a pcap on a port, we capture this value as the "start time" for that pcap stream
        //all future packet timestamps for that stream are relative to this start time
        uint64_t now_ns = ppr_now_ns();

        /* ------------------------------------- Iterate over all ports in the global port list -----------------------*/
        for (uint16_t port_idx =0; port_idx < num_ports; port_idx++){
            
            /* ---------------------------------- Get port entry and validate its present and configured to transmit ----------------------*/
            ppr_port_entry_t *port_entry = &global_port_list->ports[port_idx];
            //skip ports that are not tx enabled 
            if (atomic_load_explicit(&port_entry->tx_enabled, memory_order_acquire) == false){
                continue;
            }

            /* ---------------------------------- Get per port stream context and validate it ----------------------*/
            uint16_t port_id     = port_entry->port_id;
            uint16_t tx_queue_id = tx_worker_ctx->queue_id_by_port[port_idx];
            ppr_port_stream_ctx_t *port_stream_ctx = &tx_worker_ctx->port_stream[port_idx];

            if (port_stream_ctx == NULL){
                PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Port stream context is NULL for port index %u\n", port_idx);
                continue;
            }
            uint32_t slot_id = atomic_load_explicit(&port_stream_ctx->slot_id, memory_order_acquire);
            if (slot_id == UINT32_MAX) {
                PPR_LOG(PPR_LOG_DP, RTE_LOG_DEBUG, "No pcap slot assigned for port index %u\n", port_idx);
                continue;
            }

            //figure out our epoch and phase for this stream context
            if (port_stream_ctx->pace_mode == VC_PACE_PCAP_TS) {
                uint64_t w = port_stream_ctx->replay_window_ns;
                if (unlikely(w == 0)) {
                    PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Replay window ns is 0 for port index %u\n", port_idx);
                    continue;
                }
            }
    
            uint64_t elapsed = now_ns - port_stream_ctx->global_start_ns;
            uint64_t epoch = elapsed / port_stream_ctx->replay_window_ns;
            uint64_t phase = elapsed % port_stream_ctx->replay_window_ns;

            /* ---------------------------------- Iterate over all virtual clients for this port ----------------------*/
            uint32_t nclients = port_stream_ctx->num_clients;
            if (nclients == 0) 
                continue;

            uint32_t start = port_stream_ctx->rr_next_client;
            uint32_t budget_clients = 32; 

            for (uint32_t k = 0; k < budget_clients && k < nclients; k++) {
                uint32_t vc_idx = (start + k) % nclients;
                ppr_vc_ctx_t *vc = &port_stream_ctx->clients[vc_idx];

                if (vc->epoch != epoch) {
                    vc->epoch = epoch;
                    vc->pcap_idx = vc->start_idx;
                    vc->flow_epoch++; 
                }

                uint16_t nb = build_tx_burst(tx_pkts, BURST_SIZE_MAX, thread_args->pcap_storage,
                                            slot_id,
                                            mbuf_ts_off, tx_pool,
                                            port_stream_ctx, vc, phase);

                if (nb) {
                    uint16_t sent = rte_eth_tx_burst(port_id, tx_queue_id, tx_pkts, nb);
                    for (uint16_t i = sent; i < nb; i++)
                        rte_pktmbuf_free(tx_pkts[i]);
                }
            }

            port_stream_ctx->rr_next_client = (start + budget_clients) % nclients;


        } /* end - for port loop */
    } /* end - while loop */
    return 0;
}

