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

#define PPR_MAX_PCAP_SLOTS 256

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

//pcap mbuff slot contains a mbuf array 
typedef struct pcap_mbuff_slot {
    unsigned int        numpackets; 
    uint32_t            repl_client_ip;
    char                pcap_name[256];
    uint64_t            start_ns; 
    uint64_t            end_ns; 
    uint64_t            delta_ns; 
    uint64_t            size_in_bytes;
    pcap_replay_t        mode; 
    mbuf_array_t        *mbuf_array; 
} pcap_mbuff_slot_t;



typedef struct pcap_storage {
    _Atomic(struct pcap_mbuff_slot*) slots[PPR_MAX_PCAP_SLOTS];
    _Atomic uint32_t published_count;
    unsigned int **slot_assignments; // keep if you want, but don't realloc it live
} pcap_storage_t;



void *run_pcap_loader_thread(void *arg);


#endif