/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: tx_worker.h 
Description: header file for tx worker code 

*/

#ifndef TX_WORKER_H
#define TX_WORKER_H

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <limits.h>

#include "wpr_pcap_loader.h"
#include "wpr_mbuf_fields.h"

#define CACHE_LINE 64
#define BURST_SIZE_MAX  256

#define MAX_VC_PER_WORKER 8192

/* ------------------------------- Virtual Client Structs ---------------------------------------- */

//how to set the start time for a virtual client
typedef enum wpr_vc_start_mode {
    VC_START_RANDOM_INDEX = 0,
    VC_START_FIXED_INDEX  = 2,
} wpr_vc_start_mode_t;

//how to pace the virtual client transmissions
typedef enum wpr_vc_pace_mode {
    VC_PACE_NONE = 0,      // blast
    VC_PACE_PCAP_TS = 1,   // follow capture deltas
} wpr_vc_pace_mode_t;


// identity profile for a virtual client
typedef struct wpr_vc_identity_profile {
    // inclusive ranges (host byte order)
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;

    uint16_t src_port_lo, src_port_hi;
    uint16_t dst_port_lo, dst_port_hi;

    uint8_t  src_mac_base[6];
    uint8_t  dst_mac_base[6];
    uint32_t mac_stride; 
} wpr_vc_identity_profile_t;


//track a virtual client context 
typedef struct __attribute__((aligned(CACHE_LINE))) wpr_vc_ctx {
    // ---- hot fields ----
    uint32_t start_idx;           // chosen at init
    uint32_t pcap_idx;            // current index
    uint64_t start_offset_ns;     // chosen at init, in [0, period_ns)
    uint64_t base_rel_ns;         // template_rel_ns at start_idx
    uint64_t epoch;               // current replay epoch observed
    uint64_t flow_epoch;          // increments each epoch for tuple uniqueness
    uint32_t emit_budget;     // for non pacing modes (VC_PACE_NONE) how many packets to tx before yielding to next vc


    //these are what is actually used to do dynamic replacement 
    //values derived from identity profile. 
    uint32_t src_ip; 
    uint32_t dst_ip;
    uint16_t src_port; 
    uint16_t dst_port;
    
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];

    uint32_t local_client_idx;
    uint32_t global_client_id;
    
} wpr_vc_ctx_t;


//map workers to ports they serve
typedef struct wpr_port_worker_map {
    uint16_t W;       // workers serving this port
    uint16_t rank;    // my rank within those workers [0..W-1]
} wpr_port_worker_map_t;


//handle coordination of port streams and their virtual clients across all workers
typedef struct wpr_port_stream_global {
    //how many vc clients are active on this port
    _Atomic uint32_t active_clients; 

    // which PCAP slot this port is currently assigned
    _Atomic uint32_t slot_id;     // UINT32T_MAX means idle

    uint32_t max_clients;
    uint64_t run_seed;

    // per-port VC config 
    wpr_vc_pace_mode_t pace_mode;
    wpr_vc_start_mode_t start_mode;
    uint32_t stream_start_index; // for FIXED_INDEX mode


    // global start ns time for relative pcap timestamps
    _Atomic uint64_t global_start_ns;
    uint64_t replay_window_ns;    // period

    _Atomic uint64_t run_gen;

    wpr_vc_identity_profile_t idp;
} wpr_port_stream_global_t;


typedef struct __attribute__((aligned(64))) wpr_port_stream_ctx {
    // virtual clients for THIS port stream
    wpr_vc_ctx_t *clients;
    uint32_t num_clients;
    uint32_t last_start_gid;
    uint32_t last_count;
    uint64_t last_run_gen;

    //global port stream config pointer
    wpr_port_stream_global_t *global_cfg;

    // pacing / scheduling knobs
    uint32_t rr_next_client;      // round-robin pointer
} wpr_port_stream_ctx_t;


typedef struct __attribute__((aligned(64))) wpr_tx_worker_ctx {
    uint32_t worker_id;
    uint64_t run_seed;

    // number of ports this worker serves
    uint16_t num_ports;

    // one stream ctx per port-id for O(1)
    wpr_port_stream_ctx_t port_stream[MAX_PORTS];
    wpr_port_worker_map_t map_by_port[MAX_PORTS];
    uint16_t queue_id_by_port[MAX_PORTS];

    const void *action_table;
} wpr_tx_worker_ctx_t;


/** 
* Slice N items among W workers, returning start index and count for given rank
* @param N Total number of items    
* @param W Total number of workers
* @param rank Rank of this worker [0..W-1]
* @param start Pointer to store start index
* @param count Pointer to store count of items for this worker
**/
static inline void wpr_vc_slice(uint32_t N, uint16_t W, uint16_t rank,
                            uint32_t *start, uint32_t *count)
{
    uint32_t base = (W ? (N / W) : 0);
    uint32_t rem  = (W ? (N % W) : 0);

    uint32_t c = base + ((uint32_t)rank < rem ? 1u : 0u);
    uint32_t s = (uint32_t)rank * base + ((uint32_t)rank < rem ? (uint32_t)rank : rem);

    *start = s;
    *count = c;
}

static inline uint32_t span_u32(uint32_t lo, uint32_t hi) {
    return (hi >= lo) ? (hi - lo + 1) : 1;
}
static inline uint32_t span_u16(uint16_t lo, uint16_t hi) {
    return (hi >= lo) ? (uint32_t)(hi - lo + 1) : 1;
}

static inline void vc_materialize_identity(wpr_vc_ctx_t *vc,
                                           const wpr_vc_identity_profile_t *idp,
                                           uint16_t port_id,          // optional: salt uniqueness per port
                                           uint32_t global_vc_id)
{
    uint32_t id = global_vc_id;

    vc->global_client_id = id;

    /* ---- IPs: unique if span >= max ---- */
    uint32_t sspan = span_u32(idp->src_ip_lo, idp->src_ip_hi);
    uint32_t dspan = span_u32(idp->dst_ip_lo, idp->dst_ip_hi);

    vc->src_ip = idp->src_ip_lo + (id % sspan);
    vc->dst_ip = idp->dst_ip_lo + (id % dspan);

    /* ---- Ports: unique if span >= max ---- */
    uint32_t psspan = span_u16(idp->src_port_lo, idp->src_port_hi);
    uint32_t pdspan = span_u16(idp->dst_port_lo, idp->dst_port_hi);

    vc->src_port = (uint16_t)(idp->src_port_lo + (id % psspan));
    vc->dst_port = (uint16_t)(idp->dst_port_lo + (id % pdspan));

    /* ---- MACs: base + stride * id ---- */
    memcpy(vc->src_mac, idp->src_mac_base, 6);
    memcpy(vc->dst_mac, idp->dst_mac_base, 6);

    uint32_t add = idp->mac_stride * id;

    uint32_t tail;
    memcpy(&tail, &vc->src_mac[2], 4);
    tail = rte_be_to_cpu_32(tail) + add;
    tail = rte_cpu_to_be_32(tail);
    memcpy(&vc->src_mac[2], &tail, 4);

    memcpy(&tail, &vc->dst_mac[2], 4);
    tail = rte_be_to_cpu_32(tail) + add;
    tail = rte_cpu_to_be_32(tail);
    memcpy(&vc->dst_mac[2], &tail, 4);

    (void)port_id; /* if unused */
}



/* ----------------------- Inlined helper functions for virtual client field selection -------------------------------------- */

/** 
* SplitMix64 PRNG step function
* @param x Pointer to the current state
* @return Next pseudo-random value
**/
static inline uint64_t splitmix64_next(uint64_t *x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}


/** 
* Generate a pseudo-random value for a virtual client field based on various inputs
* @param seed Base seed value
* @param global_client_id Global unique client identifier
* @param tmpl_idx Template packet index
* @param copy_idx Copy index for multiple copies per template packet
* @param flow_epoch Flow epoch for the virtual client
* @return Pseudo-random value   
**/
static inline uint64_t vc_field_rng(uint64_t seed,
                                    uint32_t global_client_id,
                                    uint32_t tmpl_idx,
                                    uint32_t copy_idx,
                                    uint32_t flow_epoch)
{
    uint64_t x = seed;
    x ^= ((uint64_t)global_client_id << 32) | (uint64_t)tmpl_idx;
    x ^= ((uint64_t)copy_idx << 32) | (uint64_t)flow_epoch;
    // run splitmix once to avalanche
    return splitmix64_next(&x);
}

/** 
* Get the relative timestamp in nanoseconds from an mbuf's private area
* @param m Pointer to the mbuf
* @param mbuf_ts_off Offset of the timestamp field in the mbuf private area
* @return Relative timestamp in nanoseconds
**/
static inline uint64_t wpr_slot_pkt_rel_ns(const pcap_mbuff_slot_t *slot, uint32_t i, int mbuf_ts_off)
{   
    return slot->mbuf_array->pkts[i] ? my_ts_get(slot->mbuf_array->pkts[i], mbuf_ts_off) : UINT64_MAX;
}

/** 
* Find the lower bound index for a target relative timestamp in a pcap slot
* @param slot Pointer to the pcap mbuf slot
* @param n Number of packets in the slot
* @param target_rel_ns Target relative timestamp in nanoseconds
* @param mbuf_ts_off Offset of the timestamp field in the mbuf private area
* @return Index of the first packet with a relative timestamp >= target_rel_ns
**/
static inline uint32_t lower_bound_rel_ns(const pcap_mbuff_slot_t *slot, uint32_t n,
                   uint64_t target_rel_ns, int mbuf_ts_off)
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint64_t v = wpr_slot_pkt_rel_ns(slot, mid, mbuf_ts_off);
        if (v < target_rel_ns) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= n) lo = n - 1;
    return lo;
}


/** 
* Initialize virtual client start parameters
* @param vc Pointer to the virtual client context
* @param gcfg Pointer to the global port stream configuration
* @param slot Pointer to the pcap mbuf slot assigned to this port
* @param mbuf_ts_off Offset of the timestamp field in the mbuf dynfield area
* @param port_idx Port index for salting
* @param gid Global unique client ID
* @param vc_local_idx Local index of this VC within the port stream
* @param vc_count Total number of VCs in the port stream    
**/
static inline void wpr_vc_init_start_params(wpr_vc_ctx_t *vc,
                         const wpr_port_stream_global_t *gcfg,
                         const pcap_mbuff_slot_t *slot,
                         int mbuf_ts_off,
                         uint16_t port_idx,
                         uint32_t slot_id,
                         uint32_t gid,
                         uint32_t vc_local_idx,
                         uint32_t vc_count)
{
    const uint32_t n = (uint32_t)slot->numpackets;

    vc->epoch = 0;
    vc->flow_epoch = 0;

    if (n == 0) {
        vc->start_idx = vc->pcap_idx = 0;
        vc->start_offset_ns = 0;
        vc->base_rel_ns = 0;
        return;
    }

    /* deterministic per-(port,slot,gid) */
    uint64_t seed = ((uint64_t)gid << 32)
                  ^ (uint64_t)slot_id
                  ^ ((uint64_t)port_idx << 16)
                  ^ (uint64_t)vc_local_idx;
    uint64_t r = splitmix64_next(&seed);

    /* base index for FIXED mode */
    uint32_t base_idx = gcfg->stream_start_index;
    if (base_idx >= n) base_idx = 0;

    uint32_t start_idx = 0;
    uint64_t start_offset_ns = 0;

    /* ---------------- paced (pcap timestamps) ---------------- */
    if (gcfg->pace_mode == VC_PACE_PCAP_TS && gcfg->replay_window_ns > 0) {
        const uint64_t window = gcfg->replay_window_ns;

        /*
         * To guarantee "full pcap fits in the window" for each VC, we must
         * restrict the offset to [0, window - pcap_span].
         */
        uint64_t first = wpr_slot_pkt_rel_ns(slot, 0, mbuf_ts_off);
        uint64_t last  = wpr_slot_pkt_rel_ns(slot, n - 1, mbuf_ts_off);
        if (first == UINT64_MAX) first = 0;
        if (last  == UINT64_MAX) last  = first;

        uint64_t span = (last >= first) ? (last - first) : 0;

        /* If span >= window, no offset can fit the whole capture; clamp to 0. */
        uint64_t max_off = (window > span) ? (window - span) : 0;

        /*
         * Evenly distribute offsets across [0, max_off] with small jitter.
         * NOTE: if max_off == 0, all VCs necessarily align at offset 0.
         */
        uint64_t phase = (vc_count ? (max_off * (uint64_t)vc_local_idx) / (uint64_t)vc_count : 0);

        uint64_t jitter_max = (max_off / 100);          /* 1% of allowed offset range */
        uint64_t jitter = (jitter_max ? (r % jitter_max) : 0);

        start_offset_ns = (max_off ? ((phase + jitter) % (max_off + 1)) : 0);

        /*
         * IMPORTANT: for paced replay + randomized offset, keep start_idx at the
         * start of the capture so every VC replays the full pcap timeline and
         * the offset alone determines placement in the window.
         */
        start_idx = 0;

        vc->start_idx = start_idx;
        vc->pcap_idx = start_idx;
        vc->start_offset_ns = start_offset_ns;
        vc->base_rel_ns = first;   /* base relative time = first packet ts */

        return;
    }

    /* ---------------- unpaced ---------------- */
    /*
     * Unpaced: spread by packet index.
     * - RANDOM_INDEX: pseudo-random
     * - FIXED_INDEX: base + spacing
     */
    if (gcfg->start_mode == VC_START_RANDOM_INDEX) {
        start_idx = (uint32_t)(r % n);
    } else {
        uint32_t stride = (vc_count ? (n / vc_count) : n);
        if (stride == 0) stride = 1;

        start_idx = (base_idx + vc_local_idx * stride) % n;
        if (stride > 1) start_idx = (start_idx + (uint32_t)(r % stride)) % n;
    }

    start_offset_ns = 0;

    vc->start_idx = start_idx;
    vc->pcap_idx = start_idx;
    vc->start_offset_ns = start_offset_ns;

    /*
     * CRITICAL: base_rel_ns must be the template timestamp at start_idx,
     * because build_tx_burst does: rel = rel_ts - base_rel_ns.
     */
    uint64_t rel0 = wpr_slot_pkt_rel_ns(slot, start_idx, mbuf_ts_off);
    if (rel0 == UINT64_MAX) rel0 = 0;
    vc->base_rel_ns = rel0;
}


/** 
* Pick a uint32_t in the inclusive range [lo, hi] using the provided random value
* @param r Pseudo-random value
* @param lo Lower bound (inclusive)
* @param hi Upper bound (inclusive)
* @return Selected uint32_t value
**/
static inline uint32_t pick_u32(uint64_t r, uint32_t lo, uint32_t hi) {
    uint32_t span = (hi >= lo) ? (hi - lo + 1) : 1;
    return lo + (uint32_t)(r % span);
}

/** 
* Pick a uint16_t in the inclusive range [lo, hi] using the provided random value
* @param r Pseudo-random value
* @param lo Lower bound (inclusive) 
* @param hi Upper bound (inclusive)
* @return Selected uint16_t value
**/
static inline uint16_t pick_u16(uint64_t r, uint16_t lo, uint16_t hi) {
    uint32_t span = (hi >= lo) ? (uint32_t)(hi - lo + 1) : 1;
    return (uint16_t)(lo + (uint16_t)(r % span));
}

int run_tx_worker(__rte_unused void *arg);


#endif