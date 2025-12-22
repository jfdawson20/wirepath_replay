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
#include <limits.h>

#include "ppr_pcap_loader.h"

#define CACHE_LINE 64
#define BURST_SIZE_MAX  256

/* ------------------------------- Virtual Client Structs ---------------------------------------- */

//how to set the start time for a virtual client
typedef enum ppr_vc_start_mode {
    VC_START_RANDOM_INDEX = 0,
    VC_START_FIXED_INDEX  = 2,
} ppr_vc_start_mode_t;

//how to pace the virtual client transmissions
typedef enum ppr_vc_pace_mode {
    VC_PACE_NONE = 0,      // blast
    VC_PACE_PCAP_TS = 1,   // follow capture deltas
} ppr_vc_pace_mode_t;


// identity profile for a virtual client
typedef struct ppr_vc_identity_profile {
    // inclusive ranges (host byte order)
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;

    uint16_t src_port_lo, src_port_hi;
    uint16_t dst_port_lo, dst_port_hi;

    uint8_t  src_mac_base[6];
    uint8_t  dst_mac_base[6];
    uint32_t mac_stride; 
} ppr_vc_identity_profile_t;


//track a virtual client context 
typedef struct __attribute__((aligned(CACHE_LINE))) ppr_vc_ctx {
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
    
} ppr_vc_ctx_t;


typedef struct __attribute__((aligned(64))) ppr_port_stream_ctx {
    // which PCAP slot this port is currently assigned
    _Atomic uint32_t slot_id;     // UNASSIGNED means idle
    uint32_t last_seen_epoch;     // to detect slot changes (or use per-port epoch)

    // virtual clients for THIS port stream
    ppr_vc_ctx_t *clients;
    uint32_t num_clients;

    // per-port VC config (can differ per port)
    uint32_t clients_per_worker;
    uint16_t copies_per_template_pkt;
    ppr_vc_pace_mode_t pace_mode;
    ppr_vc_start_mode_t start_mode;
    ppr_vc_identity_profile_t idp;

    // pacing / scheduling knobs
    uint32_t rr_next_client;      // round-robin pointer
    uint64_t stream_seed_salt;    // derived from run_seed ^ port_id (optional)

    // global start ns time for relative pcap timestamps
    uint64_t global_start_ns;
    uint64_t replay_window_ns;    // period
} ppr_port_stream_ctx_t;


typedef struct __attribute__((aligned(64))) ppr_tx_worker_ctx {
    uint32_t worker_id;
    uint64_t run_seed;

    // ports this worker services
    uint16_t ports[MAX_PORTS];         // or a small vector
    uint16_t num_ports;

    // one stream ctx per port-id for O(1)
    ppr_port_stream_ctx_t port_stream[MAX_PORTS];

    // tx resources (if you truly do one queue per port per worker, store per port)
    struct rte_mempool *tx_pool;
    uint16_t queue_id_by_port[MAX_PORTS];

    const void *action_table;
} ppr_tx_worker_ctx_t;
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