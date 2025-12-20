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


typedef enum pcap_cmd {
    CMD_NONE,
    CMD_LOAD_PCAP,
    CMD_EXIT
} pcap_cmd_t;

typedef enum pcap_replay {
    UNASSIGNED,
    REPLAY_DIRECT,
    DYN_EXPAND
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

typedef struct pcap_storage {
    struct pcap_mbuff_slot *slots;  // dynamic array of slots
    size_t count;                   // number of slots currently in use
    size_t capacity;                // allocated size of slots array
    unsigned int **slot_assignments;  // which slot is assigned to which output port and by tx core
} pcap_storage_t;

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
    struct mbuf_array   *mbuf_array; 
} pcap_mbuff_slot_t;

typedef struct mbuf_array {
    struct rte_mbuf **pkts;   // array of mbuf pointers
    size_t count;             // how many are used
    size_t capacity;          // how many allocated
} mbuf_array_t;

//struct for dynamic client flow expansion
typedef struct virtual_flow { 
    uint32_t                vert_flow_index;
    uint64_t                offset_ns;         //when to start in reference to a comment start signal
    int64_t                 start_time_ns;         //when to start in reference to a comment start signal
    int64_t                 cur_time_ns;         //when to start in reference to a comment start signal
    bool                    running;
    unsigned int            tx_pkt_index;      //index of last transmitted packet
} virtual_flow_t;

void *run_pcap_loader_thread(void *arg);


#endif