/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: app_defines.h
Description: header file containing app wide constants and structs

*/

#ifndef APP_DEFINE_H
#define APP_DEFINE_H
#include <rte_log.h>
#include <rte_mempool.h>

#include <signal.h>
#include <stdatomic.h>   

//pcap mbuf 
#define NUM_MBUFS 1000000
#define MBUF_CACHE_SIZE 256
#define PCAP_READ_CHUNK 256

//per core clone mbuffs
#define NUM_CLONE_MBUFS 8192
#define CLONE_MBUF_CACHE_SIZE 256

#define MAX_PORTS 8 

/* Forward declarations for types only used via pointer in this header */
typedef struct ppr_global_policy_epoch  ppr_global_policy_epoch_t;   
typedef struct ppr_acl_rule_db          ppr_acl_rule_db_t;
typedef struct ppr_acl_runtime          ppr_acl_runtime_t;
typedef struct ppr_rcu_ctx              ppr_rcu_ctx_t;
typedef struct ppr_ports                ppr_ports_t; 
typedef struct ppr_stats_all            ppr_stats_all_t;
typedef struct pcap_loader_ctl          pcap_loader_ctl_t;
typedef struct pcap_storage             pcap_storage_t;
typedef struct ppr_tx_worker_ctx        ppr_tx_worker_ctx_t;
typedef struct ppr_port_stream_global   ppr_port_stream_global_t;

/* per thread struct with globals */
typedef struct ppr_thread_args{

    //identifiers
    unsigned int            core_id; 
    unsigned int            thread_index;
    unsigned int            num_tx_cores;
    unsigned int            poll_period_ms;
    _Atomic  bool           *app_ready;      //written by main, read by threads, common
    _Atomic  bool           thread_ready;    //written by thread, read by main, one per thread

    //traffic gen control/status
    ppr_tx_worker_ctx_t      *tx_worker_ctx; //used by tx workers only
    ppr_port_stream_global_t *port_stream_global_cfg; //pointer to list of global port stream configs
    int                      mbuf_ts_off;

    //stats & control structs
    ppr_ports_t             *global_port_list;
    ppr_stats_all_t         *global_stats;

    //pcap loader / storage interfaces 
    pcap_loader_ctl_t       *pcap_controller;
    pcap_storage_t          *pcap_storage;

    //mempool pointers
    struct rte_mempool      *pcap_template_mpool;
    struct rte_mempool      *txcore_copy_mpools;

    //QSBR Context
    ppr_rcu_ctx_t              *rcu_ctx;

    //acl rules interface 
    ppr_acl_rule_db_t            *acl_rule_db;
    ppr_acl_runtime_t            *acl_runtime;

    //app controller settings
    int                         controller_port;


} ppr_thread_args_t;


struct core_mapping {
    unsigned int tx_core; 
    unsigned int *filler_cores;
    unsigned int total_fillers;
};


//global app failure flag and fatal error function
extern _Atomic int wps_fatal_error;
extern volatile sig_atomic_t force_quit;

void ppr_fatal(const char *fmt, ...);

#endif 