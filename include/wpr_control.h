/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: control.h
Description: header file for control server and related structs

*/

#ifndef CONTROL_H
#define CONTROL_H

#include <pthread.h> 
#include <stdbool.h>
#include <rte_mempool.h>
#include <stdatomic.h>
#include <jansson.h>

#include "wpr_app_defines.h"

#define MAX_SOCK_PAYLOAD 65536

void *run_control_server(void *arg);

struct port_tx_config {
    bool start;
};

struct psmith_app_state {
    pthread_mutex_t         lock; 
    int                     mbuf_ts_off;
    unsigned int            num_tx_cores;
    unsigned int            num_buf_cores;
    bool                    app_initialized; 
    unsigned int            ports_configured; 
    unsigned int            *port_status; // per port
    volatile unsigned int   *port_enable;
    volatile unsigned int   *virt_channels_per_port;
    struct core_mapping     *tx_buff_core_mapping;
    struct rte_mempool      *pcap_template_mpool;
    struct rte_mempool      **txcore_clone_mpools;
    struct pcap_storage     *pcap_storage_t; 
};

/* Handler prototype for all commands */
typedef int (*wpr_cmd_handler_t)(json_t *reply_root,
                                 json_t *args,
                                 wpr_thread_args_t *thread_args);

/* One entry per command */
typedef struct {
    const char        *name;        /* "ping", "port_stats", ... */
    const char        *description; /* human-readable */
    const char        *args_schema; /* optional doc/JSON-schema-ish */
    wpr_cmd_handler_t  handler;     /* function to call */
} wpr_cmd_def_t;

/* Table + size exported by control_server.c */
extern const wpr_cmd_def_t wpr_cmd_table[];
extern const size_t        wpr_cmd_table_count;

/* Helper for lookup by JSON "cmd" string */
const wpr_cmd_def_t *wpr_control_find_cmd(const char *name);

/* Helper to build a JSON "help" document for clients */
json_t *wpr_control_build_help_doc(void);

void *run_wpr_app_server_thread(void *arg);


#endif