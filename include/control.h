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

#endif