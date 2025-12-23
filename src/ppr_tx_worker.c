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
#include "ppr_header_extract.h"


#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_mbuf.h>

#include "ppr_mbuf_fields.h"
#include "ppr_actions.h"
#include "ppr_tx_worker.h"      // for ppr_vc_ctx_t
#include "ppr_header_extract.h" // for ppr_parse_headers + ppr_hdrs_t

/* ---------------- checksum helpers (recompute) ---------------- */

static inline uint16_t csum16_reduce(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint32_t csum_add_buf(uint32_t sum, const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    while (len >= 2) {
        sum += *p++;
        len -= 2;
    }
    if (len) /* odd tail */
        sum += *(const uint8_t *)p;
    return sum;
}

static inline uint16_t ipv4_hdr_checksum(struct rte_ipv4_hdr *ip)
{
    ip->hdr_checksum = 0;
    uint32_t sum = 0;
    uint16_t ihl = (uint16_t)((ip->version_ihl & 0x0F) * 4);
    sum = csum_add_buf(sum, ip, ihl);
    return csum16_reduce(sum);
}

static inline uint32_t ipv4_pseudo_sum(const struct rte_ipv4_hdr *ip, uint16_t l4_len, uint8_t proto)
{
    uint32_t sum = 0;
    /* ip->src_addr/dst_addr are in network order */
    sum += (uint16_t)(ip->src_addr >> 16);
    sum += (uint16_t)(ip->src_addr & 0xFFFF);
    sum += (uint16_t)(ip->dst_addr >> 16);
    sum += (uint16_t)(ip->dst_addr & 0xFFFF);
    sum += rte_cpu_to_be_16((uint16_t)proto);
    sum += rte_cpu_to_be_16(l4_len);
    return sum;
}

static inline uint16_t l4_checksum_ipv4(const struct rte_ipv4_hdr *ip, void *l4, uint16_t l4_len, uint8_t proto)
{
    uint32_t sum = ipv4_pseudo_sum(ip, l4_len, proto);
    sum = csum_add_buf(sum, l4, l4_len);
    return csum16_reduce(sum);
}

/* ---------------- rewrite helpers ---------------- */

static inline void clear_rss_hash(struct rte_mbuf *m)
{
    m->hash.rss = 0;
    m->ol_flags &= ~RTE_MBUF_F_RX_RSS_HASH;
}

/* Return true if caller should drop/free */
static bool ppr_modify_mbuf(struct rte_mbuf *m, const ppr_vc_ctx_t *vc)
{
    if (unlikely(m == NULL || vc == NULL))
        return true;

    ppr_priv_t *priv = ppr_priv(m);

    /* If action isn't valid, do nothing */
    if (!priv->pending_policy_action.valid)
        return false;

    /* Parse packet headers (offsets, L3/L4, etc.) */
    ppr_hdrs_t hdrs;
    int rc = ppr_parse_headers(m, &hdrs);
    if (rc < 0)
        return false; /* can't safely edit -> treat as NOOP */

    ppr_flow_action_kind_t act = priv->pending_policy_action.default_policy;

    if (act == FLOW_ACT_NOOP)
        return false;
    if (act == FLOW_ACT_DROP)
        return true;

    /* We only implement OUTER L2 + OUTER IPv4 + TCP/UDP here */
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    bool changed_l2 = false;
    bool changed_ip = false;
    bool changed_l4 = false;

    /* ---------- L2 ---------- */
    if (act == FLOW_ACT_MODIFY_SRCMAC || act == FLOW_ACT_MODIFY_SRC_ALL || act == FLOW_ACT_MODIFY_ALL) {
        /* vc->src_mac is uint8_t[6] per your struct */
        memcpy(&eth->src_addr, vc->src_mac, RTE_ETHER_ADDR_LEN);
        changed_l2 = true;
    }

    if (act == FLOW_ACT_MODIFY_DSTMAC || act == FLOW_ACT_MODIFY_DST_ALL || act == FLOW_ACT_MODIFY_ALL) {
        memcpy(&eth->dst_addr, vc->dst_mac, RTE_ETHER_ADDR_LEN);
        changed_l2 = true;
    }

    /* ---------- L3/L4 (IPv4 only in this version) ---------- */
    if (hdrs.l3_type == PPR_L3_IPV4) {
        struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdrs.outer_l3_ofs);

        if (act == FLOW_ACT_MODIFY_SRCIP || act == FLOW_ACT_MODIFY_SRC_ALL || act == FLOW_ACT_MODIFY_ALL) {
            ip4->src_addr = rte_cpu_to_be_32(vc->src_ip); /* vc is host-order */
            changed_ip = true;
        }
        if (act == FLOW_ACT_MODIFY_DSTIP || act == FLOW_ACT_MODIFY_DST_ALL || act == FLOW_ACT_MODIFY_ALL) {
            ip4->dst_addr = rte_cpu_to_be_32(vc->dst_ip);
            changed_ip = true;
        }

        /* L4 ports only if TCP/UDP */
        if (hdrs.l4_type == PPR_L4_TCP) {
            struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdrs.outer_l4_ofs);

            if (act == FLOW_ACT_MODIFY_SRCPORT || act == FLOW_ACT_MODIFY_SRC_ALL || act == FLOW_ACT_MODIFY_ALL) {
                tcp->src_port = rte_cpu_to_be_16(vc->src_port);
                changed_l4 = true;
            }
            if (act == FLOW_ACT_MODIFY_DSTPORT || act == FLOW_ACT_MODIFY_DST_ALL || act == FLOW_ACT_MODIFY_ALL) {
                tcp->dst_port = rte_cpu_to_be_16(vc->dst_port);
                changed_l4 = true;
            }

            /* Recompute checksums if any relevant field changed */
            if (changed_ip || changed_l4) {
                ip4->hdr_checksum = ipv4_hdr_checksum(ip4);

                uint16_t ihl = (uint16_t)((ip4->version_ihl & 0x0F) * 4);
                uint16_t tot_len = rte_be_to_cpu_16(ip4->total_length);
                uint16_t l4_len = (tot_len > ihl) ? (uint16_t)(tot_len - ihl) : 0;

                tcp->cksum = 0;
                tcp->cksum = l4_checksum_ipv4(ip4, tcp, l4_len, IPPROTO_TCP);
            }

        } else if (hdrs.l4_type == PPR_L4_UDP) {
            struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, hdrs.outer_l4_ofs);

            if (act == FLOW_ACT_MODIFY_SRCPORT || act == FLOW_ACT_MODIFY_SRC_ALL || act == FLOW_ACT_MODIFY_ALL) {
                udp->src_port = rte_cpu_to_be_16(vc->src_port);
                changed_l4 = true;
            }
            if (act == FLOW_ACT_MODIFY_DSTPORT || act == FLOW_ACT_MODIFY_DST_ALL || act == FLOW_ACT_MODIFY_ALL) {
                udp->dst_port = rte_cpu_to_be_16(vc->dst_port);
                changed_l4 = true;
            }

            if (changed_ip || changed_l4) {
                ip4->hdr_checksum = ipv4_hdr_checksum(ip4);

                /* UDP length field already in header */
                uint16_t l4_len = rte_be_to_cpu_16(udp->dgram_len);

                udp->dgram_cksum = 0;
                udp->dgram_cksum = l4_checksum_ipv4(ip4, udp, l4_len, IPPROTO_UDP);
            }

        } else {
            /* non TCP/UDP: if IP changed, still fix IPv4 hdr checksum */
            if (changed_ip) {
                ip4->hdr_checksum = ipv4_hdr_checksum(ip4);
            }
        }

    } else {
        /* IPv6 or non-IP: not implemented here */
        /* If you changed L2 only, that's fine; no IP checksum work needed. */
    }

    /* If we changed anything that affects a 5-tuple / flow hash, clear RSS hash validity */
    if (changed_ip || changed_l4) {
        clear_rss_hash(m);
    }

    (void)changed_l2;
    return false;
}




/** 
* Build a burst of packets to transmit for a given virtual client on a port stream context.
* @param tx_pkts
*   Array to populate with packets to transmit.
* @param max_pkts
*   Maximum number of packets to add to the burst.
* @param pcap_storage
*   Pointer to the global pcap storage structure.
* @param slot_id
*   Slot ID of the pcap to read packets from.
* @param mbuf_ts_off
*   Offset of the timestamp field in the mbuf private area.
* @param tx_pool
*   Mempool to allocate cloned mbufs from.
* @param psc
*   Pointer to the port stream context.
* @param vc
*   Pointer to the virtual client context.
* @param phase
*   Current phase time for pacing.
* @return
*   Number of packets added to the burst.
**/
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

    //get the pointer to the pcap mbuf slot
    pcap_mbuff_slot_t *slot = atomic_load_explicit(&pcap_storage->slots[slot_id], memory_order_acquire);
    if (!slot || !slot->mbuf_array || !slot->mbuf_array->pkts)
        return 0;

    //while we have budget and packets in this vc's pcap stream
    while (nb < max_pkts && vc->pcap_idx < slot->numpackets) {
        
        //get the next template mbuf from the pcap slot
        struct rte_mbuf *tmpl = slot->mbuf_array->pkts[vc->pcap_idx];
        if (!tmpl) break;

        //if we are pacing based on pcap timestamps, check if this packet is due yet
        if (psc->global_cfg->pace_mode == VC_PACE_PCAP_TS) {
            uint64_t rel_ts = my_ts_get(tmpl, mbuf_ts_off);
            if (unlikely(rel_ts < vc->base_rel_ns)) {
                break; // end VC for this epoch
            }
            uint64_t rel = rel_ts - vc->base_rel_ns;  
            uint64_t pkt_phase = (vc->start_offset_ns + rel) % psc->global_cfg->replay_window_ns;
            if (pkt_phase > phase) 
                break; // not time yet

        }

        // create a packet copy since we may need to modify it 
        struct rte_mbuf *c = ppr_copy_with_priv(tmpl, tx_pool);
        if (unlikely(c == NULL)) {
            printf("failed to copy\n");
            break; // pool pressure: just send the ones we cloned
        }

        //apply any packet modifications
        if (unlikely(ppr_modify_mbuf(c, vc))) {
            rte_pktmbuf_free(c);
            continue;
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
    struct rte_mempool              *tx_pool = thread_args->txcore_copy_mpools;
    uint16_t                         mbuf_ts_off = thread_args->mbuf_ts_off; 
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
            uint16_t dpdk_port_id = port_entry->port_id;
            uint16_t tx_queue_id  = tx_worker_ctx->queue_id_by_port[port_idx];
            
            ppr_port_stream_ctx_t *port_stream_ctx = &tx_worker_ctx->port_stream[port_idx];
            ppr_port_stream_global_t *g = port_stream_ctx->global_cfg;

            if(!port_stream_ctx || !g){
                PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Invalid port stream context for port index %u\n", port_idx);
                continue;
            }

            //load slot id for this port stream
            uint32_t slot_id = atomic_load_explicit(&g->slot_id, memory_order_acquire);
            if (slot_id == UINT32_MAX) {
                PPR_LOG(PPR_LOG_DP, RTE_LOG_DEBUG, "No pcap slot assigned for port index %u\n", port_idx);
                continue;
            }

            uint64_t elapsed    = now_ns - atomic_load_explicit(&g->global_start_ns, memory_order_acquire);
            uint64_t epoch      = 0;
            uint64_t phase      = 0;

            //figure out our epoch and phase for this stream context
            if (g->pace_mode == VC_PACE_PCAP_TS) {
                uint64_t w = g->replay_window_ns;
                if (unlikely(w == 0)) {
                    PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Replay window ns is 0 for port index %u\n", port_idx);
                    continue;
                }
                
                epoch = elapsed / g->replay_window_ns;
                phase = elapsed % g->replay_window_ns;

            }
    
            /* ---------------------------------- Iterate over all virtual clients for this port ----------------------*/
            
            /* Total active VCs for this port stream */
            uint32_t N = atomic_load_explicit(&g->active_clients, memory_order_acquire);
            if (N == 0) {
                port_stream_ctx->num_clients = 0;
                continue;
            }

            /* Workers serving this port + my rank among them */
            ppr_port_worker_map_t map = tx_worker_ctx->map_by_port[port_idx];
            uint16_t W = map.W;
            uint16_t rank = map.rank;

            if (W == 0 || rank >= W) {
                /* misconfigured mapping */
                continue;
            }

            /* Compute my slice */
            uint32_t start_gid = 0, count = 0;
            ppr_vc_slice(N, W, rank, &start_gid, &count);

            if (count > MAX_VC_PER_WORKER) {
                /* either clamp or treat as config error */
                count = MAX_VC_PER_WORKER;
            }

            /* If slice changed, remap local slots to the new global IDs */
            if (port_stream_ctx->last_start_gid != start_gid || port_stream_ctx->last_count != count) {

                for (uint32_t i = 0; i < count; i++) {
                    uint32_t gid = start_gid + i;
                    ppr_vc_ctx_t *vc = &port_stream_ctx->clients[i];

                    if (vc->global_client_id != gid) {
                        vc_materialize_identity(vc, &g->idp, port_idx, gid);

                        /* Reset pacing state (simple semantics) */
                        vc->epoch = 0;
                        vc->flow_epoch = 0;

                        /* You MUST also ensure start_idx/start_offset/base_rel_ns are set appropriately.
                        If you already have per-VC init logic, call it here.
                        Minimal safe defaults:
                        */
                        vc->start_idx = 0;
                        vc->pcap_idx = 0;
                        vc->start_offset_ns = 0;
                        vc->base_rel_ns = 0;
                    }
                }

                port_stream_ctx->rr_next_client = 0;
                port_stream_ctx->last_start_gid = start_gid;
                port_stream_ctx->last_count = count;
            }

            port_stream_ctx->num_clients = count;

            uint32_t nclients = port_stream_ctx->num_clients;
            if (nclients == 0) 
                continue;

            uint32_t start = port_stream_ctx->rr_next_client;
            uint32_t budget_clients = 32; 

            for (uint32_t k = 0; k < budget_clients && k < nclients; k++) {
                uint32_t vc_idx = (start + k) % nclients;
                ppr_vc_ctx_t *vc = &port_stream_ctx->clients[vc_idx];

                if (vc->epoch != epoch && g->pace_mode == VC_PACE_PCAP_TS) {
                    vc->epoch = epoch;
                    vc->pcap_idx = vc->start_idx;
                    vc->flow_epoch++; 
                }

                uint16_t nb = build_tx_burst(tx_pkts, BURST_SIZE_MAX, thread_args->pcap_storage,
                                            slot_id,
                                            mbuf_ts_off, tx_pool,
                                            port_stream_ctx, vc, phase);

                if (nb) {
                    uint16_t sent = rte_eth_tx_burst(dpdk_port_id, tx_queue_id, tx_pkts, nb);
                    for (uint16_t i = sent; i < nb; i++)
                        rte_pktmbuf_free(tx_pkts[i]);
                }
            }

            port_stream_ctx->rr_next_client = (start + budget_clients) % nclients;


        } /* end - for port loop */
    } /* end - while loop */
    return 0;
}

