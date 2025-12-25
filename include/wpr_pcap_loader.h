/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: pcap_loader.h
Description: header file for pcap_loader code and data types

*/

#ifndef PCAP_LOADER_H
#define PCAP_LOADER_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define WPR_MAX_PCAP_SLOTS 256

typedef enum pcap_cmd {
    CMD_NONE,
    CMD_LOAD_PCAP,
    CMD_APPLY_ACL_RULES,   //pre-parse and apply acl rules to loaded pcaps
    CMD_EXIT
} pcap_cmd_t;

typedef enum pcap_replay {
    UNASSIGNED,
    REPLAY_DIRECT,
    ACL_REPLAY,
} pcap_replay_t;

typedef struct pcap_loader_ctl {
    //control and status 
    pthread_mutex_t lock; 
    pthread_cond_t  cond; 
    pcap_cmd_t      command; 
    int             result; 
    bool            busy;
    
    //pcap filename
    char            filename[256];
    unsigned int    tx_core;
    unsigned int    latest_slotid;
} pcap_loader_ctl_t;


typedef struct mbuf_array {
    struct rte_mbuf **pkts;               // array of mbuf pointers
    size_t count;                         // how many are used
    size_t capacity;                      // how many allocated
    const uint32_t *cap_ts_us;            // relative timestamps (optional)
    const uint16_t *action_id;            // classification result per template pkt
} mbuf_array_t;

typedef struct wpr_pcap_rate_metrics {
    uint64_t duration_ns;          /* end_ns - start_ns */
    uint64_t total_packets;        /* numpackets */
    uint64_t total_bytes;          /* size_in_bytes */

    double   pps;                  /* packets / sec */
    double   bps;                  /* bits / sec */
    double   cps;                  /* connections / sec */

    uint64_t unique_conns;         /* unique 5-tuples (or “flows”) in template */
} wpr_pcap_rate_metrics_t;

typedef enum wpr_target_kind {
    WPR_TARGET_PPS = 1,
    WPR_TARGET_BPS = 2,
    WPR_TARGET_CPS = 3,
} wpr_target_kind_t;

typedef struct wpr_pcap_scaling_model {
    /* model coefficients: total_rate = base_rate_per_vc * vc_count */
    double base_pps_per_vc;
    double base_bps_per_vc;
    double base_cps_per_vc;

    /* configuration / limits */
    uint32_t max_vc_supported;   /* system / port limit */
    double   safety_margin;      /* e.g. 0.90 = pick VC so model total is 90% of target */
} wpr_pcap_scaling_model_t;

typedef struct wpr_pcap_last_autotune {
    wpr_target_kind_t kind;
    double   target;
    uint32_t chosen_vc;
    double   predicted_total;    /* predicted pps/bps/cps for chosen_vc */
} wpr_pcap_last_autotune_t;

typedef struct pcap_mbuff_slot {
    unsigned int        numpackets;
    uint32_t            repl_client_ip;
    char                pcap_name[256];
    uint64_t            start_ns;
    uint64_t            end_ns;
    uint64_t            delta_ns;
    uint64_t            size_in_bytes;
    pcap_replay_t       mode;
    mbuf_array_t       *mbuf_array;

    /* native template metrics (after load, and optionally after ACL “bake”) */
    wpr_pcap_rate_metrics_t native_metrics;
    
    /* NEW: scaling model derived from native_metrics */
    wpr_pcap_scaling_model_t scaling;

    /* NEW: last autotune decision for debugging/telemetry */
    wpr_pcap_last_autotune_t last_autotune;

} pcap_mbuff_slot_t;



typedef struct pcap_storage {
    _Atomic(pcap_mbuff_slot_t *) slots[WPR_MAX_PCAP_SLOTS];
    _Atomic uint32_t published_count;
} pcap_storage_t;



void *run_pcap_loader_thread(void *arg);

static inline double ns_to_sec_u64(uint64_t ns) {
    return (double)ns / 1e9;
}

#endif