/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_qsbr.c
Description: Multiple subsystems in the wpr application require read-copy-update (RCU) style synchronization for safe concurrent access to shared data 
structures. Specifically, systems that require lock-free delete/update of shared structures that are frequently read by datapath worker threads use RCU QSBR 
(quiescent state-based reclamation) provided by DPDK to ensure safe memory reclamation of retired objects. While each specific subsystem (e.g. flow table, 
load balancer) maintains their own specific QSBR differ queue and callback reclamation logic, they all share a common RCU QSBR context structure that is used 
to register reader threads and manage the underlying DPDK RCU QSBR structure.

the wpr QSBR API provides helper functions for initializing the RCU QSBR context, registering reader threads, and marking quiescent states. This allows
multiple subsystems to share a common RCU QSBR structure while encapsulating the specific logic for each subsystem's defer queue and reclamation process.

*/

#define _GNU_SOURCE

#include <stdio.h>
#include "wpr_qsbr.h"

/** 
* Initialize a reader thread for flow table access
* @param ft
*   Pointer to flow table structure
* @param thread_id
*   Thread ID of the reader thread
**/
void wpr_ft_reader_init(wpr_rcu_ctx_t *rcu_ctx, int thread_id){
    rte_rcu_qsbr_thread_register(rcu_ctx->qs, thread_id);
    rte_rcu_qsbr_thread_online(rcu_ctx->qs, thread_id);
}

/** 
* uninitialize a reader thread for flow table access
* @param ft
*   Pointer to flow table structure
* @param thread_id
*   Thread ID of the reader thread
**/
void wpr_ft_reader_destroy(wpr_rcu_ctx_t *rcu_ctx, int thread_id){
    rte_rcu_qsbr_thread_offline(rcu_ctx->qs, thread_id);
    rte_rcu_qsbr_thread_unregister(rcu_ctx->qs, thread_id);
}

/** 
* Mark the reader thread as idle for QSBR
* @param ft
*   Pointer to flow table structure
* @param thread_id
*   Thread ID of the reader thread  
**/
void wpr_ft_reader_idle(wpr_rcu_ctx_t *rcu_ctx, int thread_id){
    rte_rcu_qsbr_quiescent(rcu_ctx->qs, thread_id);
}