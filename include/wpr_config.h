/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_config.h
Description: This file contains all the libcyaml struct definitions and parsing functions for the application configuration file. 
If changes are made to the config file format, they must be reflected here and in wpr_config.c which contains the schema definitions.

*/

#ifndef WPR_CFG_H
#define WPR_CFG_H


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "wpr_actions.h"
#include "wpr_log.h"

typedef enum {
    PORT_TYPE_DATAPATH = 0,
} wpr_port_type_t;

typedef enum {
    PORT_MODE_BRIDGE = 0,
    PORT_MODE_MIRROR = 1,
} wpr_port_mode_t;


/* app_settings */
typedef struct wpr_app_settings{
    uint8_t  log_level;         /* e.g., 0..8 */
    wpr_log_mode_t default_output;    /* "stdout" */
    char    *default_log_dir;   /* "/var/log" */
    uint16_t global_rx_burst_size; /* 128 */
    uint16_t global_tx_burst_size; /* 128 */
    uint16_t controller_port;   /* 9090 */
} wpr_app_settings_t;

/* thread_settings */
typedef struct wpr_thread_settings{
    uint32_t  tx_cores;
    uint32_t  base_lcore_id;
} wpr_thread_settings_t;

/* port_settings[] entry */
typedef struct wpr_port{
    char       *name;          /* "port0" */
    wpr_port_type_t type;          /* "datapath" */
    char       *pci_bus_addr;  /* "0000:01:00.0" (quoted in YAML) */
    uint32_t   rx_ring_size;
    uint32_t   tx_ring_size;
    bool       tx_ip_checksum_offload;
    bool       tx_tcp_checksum_offload;
    bool       tx_udp_checksum_offload;
    bool       tx_multiseg_offload;
} wpr_port_t;

/* mempool_settings[] entry */
typedef struct wpr_mempool{
    char     *name;           /* "rx_mempool" */
    uint32_t  mpool_entries;  /* 65536 */
    uint32_t  mpool_cache;    /* 256 */
} wpr_mempool_t;

typedef struct wpr_acl_table_settings{
    char     *startup_cfg_file;   /* e.g., "rules.yaml" */
    uint32_t  qsbr_reclaim_size;  /* e.g., 2048 */
    uint32_t  qsbr_reclaim_limit; /* e.g., 4096 */
} wpr_acl_table_settings_t;

/* Top-level config */
typedef struct wpr_config{
    wpr_app_settings_t           app_settings;
    wpr_thread_settings_t        thread_settings;

    /* port_settings: sequence + count */
    wpr_port_t                  *port_settings;
    unsigned                    port_settings_count;

    /* mempool_settings: sequence + count */
    wpr_mempool_t               *mempool_settings;
    unsigned                    mempool_settings_count;

    wpr_acl_table_settings_t       acl_table_settings;

} wpr_config_t;

#endif /* WPR_CFG_H */