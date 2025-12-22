/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_config.h
Description: This file contains all the libcyaml struct definitions and parsing functions for the application configuration file. 
If changes are made to the config file format, they must be reflected here and in ppr_config.c which contains the schema definitions.

*/

#ifndef PPR_CFG_H
#define PPR_CFG_H


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "ppr_actions.h"
#include "ppr_log.h"

typedef enum {
    PORT_TYPE_DATAPATH = 0,
} ppr_port_type_t;

typedef enum {
    PORT_MODE_BRIDGE = 0,
    PORT_MODE_MIRROR = 1,
} ppr_port_mode_t;


/* app_settings */
typedef struct ppr_app_settings{
    uint8_t  log_level;         /* e.g., 0..8 */
    ppr_log_mode_t default_output;    /* "stdout" */
    char    *default_log_dir;   /* "/var/log" */
    uint16_t global_rx_burst_size; /* 128 */
    uint16_t global_tx_burst_size; /* 128 */
    uint16_t controller_port;   /* 9090 */
} ppr_app_settings_t;

/* thread_settings */
typedef struct ppr_thread_settings{
    uint32_t  tx_cores;
    uint32_t  base_lcore_id;
} ppr_thread_settings_t;

/* port_settings[] entry */
typedef struct ppr_port{
    char       *name;          /* "port0" */
    ppr_port_type_t type;          /* "datapath" */
    char       *pci_bus_addr;  /* "0000:01:00.0" (quoted in YAML) */
    uint32_t   rx_ring_size;
    uint32_t   tx_ring_size;
    bool       tx_ip_checksum_offload;
    bool       tx_tcp_checksum_offload;
    bool       tx_udp_checksum_offload;
    bool       tx_multiseg_offload;
} ppr_port_t;

/* mempool_settings[] entry */
typedef struct ppr_mempool{
    char     *name;           /* "rx_mempool" */
    uint32_t  mpool_entries;  /* 65536 */
    uint32_t  mpool_cache;    /* 256 */
} ppr_mempool_t;

typedef struct ppr_acl_table_settings{
    char     *startup_cfg_file;   /* e.g., "rules.yaml" */
    uint32_t  qsbr_reclaim_size;  /* e.g., 2048 */
    uint32_t  qsbr_reclaim_limit; /* e.g., 4096 */
} ppr_acl_table_settings_t;

/* Top-level config */
typedef struct ppr_config{
    ppr_app_settings_t           app_settings;
    ppr_thread_settings_t        thread_settings;

    /* port_settings: sequence + count */
    ppr_port_t                  *port_settings;
    unsigned                    port_settings_count;

    /* mempool_settings: sequence + count */
    ppr_mempool_t               *mempool_settings;
    unsigned                    mempool_settings_count;

    ppr_acl_table_settings_t       acl_table_settings;

} ppr_config_t;

#endif /* PPR_CFG_H */