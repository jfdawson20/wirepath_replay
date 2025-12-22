/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_config.c
Description: This file contains all the libcyaml schema definitions and parsing functions for the application configuration file. 
If changes are made to the config file format, they must be reflected here and in ppr_coonfig.h which contains the struct definitions.
*/

#define _GNU_SOURCE
#include <cyaml/cyaml.h>
#include "ppr_config.h"
#include "ppr_actions.h"

/* ----- enum string maps ----- */

static const cyaml_strval_t log_mode_strings[] = {
    { "stdout", LOG_STDOUT },
    { "file",   LOG_FILE },
};  

static const cyaml_strval_t port_type_strings[] = {
    { "datapath", PORT_TYPE_DATAPATH },
};


/* ----- leaf mappings ----- */
static const cyaml_schema_field_t app_settings_fields[] = {
    CYAML_FIELD_UINT       ("log_level",        CYAML_FLAG_DEFAULT, ppr_app_settings_t, log_level),
    CYAML_FIELD_ENUM       ("default_output",   CYAML_FLAG_DEFAULT, ppr_app_settings_t, default_output, log_mode_strings, CYAML_ARRAY_LEN(log_mode_strings)),
    CYAML_FIELD_STRING_PTR ("default_log_dir",  CYAML_FLAG_POINTER,  ppr_app_settings_t, default_log_dir,1, CYAML_UNLIMITED),
    CYAML_FIELD_UINT       ("global_rx_burst_size",CYAML_FLAG_DEFAULT, ppr_app_settings_t, global_rx_burst_size),
    CYAML_FIELD_UINT       ("global_tx_burst_size",CYAML_FLAG_DEFAULT, ppr_app_settings_t, global_tx_burst_size),
    CYAML_FIELD_UINT       ("controller_port",  CYAML_FLAG_DEFAULT, ppr_app_settings_t, controller_port),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t thread_settings_fields[] = {
    CYAML_FIELD_UINT("tx_cores", CYAML_FLAG_DEFAULT, ppr_thread_settings_t, tx_cores),
    CYAML_FIELD_UINT("base_lcore_id", CYAML_FLAG_DEFAULT, ppr_thread_settings_t, base_lcore_id),
    CYAML_FIELD_END
};


/* port_settings[] entry */
static const cyaml_schema_field_t port_fields[] = {
    CYAML_FIELD_STRING_PTR ("name",         CYAML_FLAG_POINTER, ppr_port_t, name,1, CYAML_UNLIMITED),
    CYAML_FIELD_ENUM       ("type",         CYAML_FLAG_DEFAULT, ppr_port_t, type, port_type_strings, CYAML_ARRAY_LEN(port_type_strings)),
    CYAML_FIELD_STRING_PTR ("pci_bus_addr", CYAML_FLAG_POINTER, ppr_port_t, pci_bus_addr, 1, CYAML_UNLIMITED),
    CYAML_FIELD_UINT       ("rx_ring_size", CYAML_FLAG_DEFAULT, ppr_port_t, rx_ring_size),
    CYAML_FIELD_UINT       ("tx_ring_size", CYAML_FLAG_DEFAULT, ppr_port_t, tx_ring_size),
    CYAML_FIELD_BOOL       ("tx_ip_checksum_offload",  CYAML_FLAG_DEFAULT, ppr_port_t, tx_ip_checksum_offload),
    CYAML_FIELD_BOOL       ("tx_tcp_checksum_offload", CYAML_FLAG_DEFAULT, ppr_port_t, tx_tcp_checksum_offload),
    CYAML_FIELD_BOOL       ("tx_udp_checksum_offload", CYAML_FLAG_DEFAULT, ppr_port_t, tx_udp_checksum_offload),
    CYAML_FIELD_BOOL       ("tx_multiseg_offload",     CYAML_FLAG_DEFAULT, ppr_port_t, tx_multiseg_offload),
    CYAML_FIELD_END
};

/* mempool_settings[] entry */
static const cyaml_schema_field_t mempool_fields[] = {
    CYAML_FIELD_STRING_PTR ("name",          CYAML_FLAG_POINTER, ppr_mempool_t, name, 1, CYAML_UNLIMITED),
    CYAML_FIELD_UINT       ("mpool_entries", CYAML_FLAG_DEFAULT, ppr_mempool_t, mpool_entries),
    CYAML_FIELD_UINT       ("mpool_cache",   CYAML_FLAG_DEFAULT, ppr_mempool_t, mpool_cache),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t acl_table_settings_fields[] = {
    CYAML_FIELD_STRING_PTR ("startup_cfg_file", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, ppr_acl_table_settings_t, startup_cfg_file, 1, CYAML_UNLIMITED),
    CYAML_FIELD_UINT       ("qsbr_reclaim_size",CYAML_FLAG_DEFAULT, ppr_acl_table_settings_t, qsbr_reclaim_size),
    CYAML_FIELD_UINT       ("qsbr_reclaim_limit",CYAML_FLAG_DEFAULT, ppr_acl_table_settings_t, qsbr_reclaim_limit),
    CYAML_FIELD_END
};


/* ----- value schemas for sequences & mappings ----- */
//don't use these currently, but may in the future
#if 0
static const cyaml_schema_value_t thread_settings_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, ppr_thread_settings_t, thread_settings_fields),
};

static const cyaml_schema_value_t app_settings_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, ppr_app_settings_t, app_settings_fields),
};
#endif 

static const cyaml_schema_value_t port_entry_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, ppr_port_t, port_fields),
};

static const cyaml_schema_value_t mempool_entry_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, ppr_mempool_t, mempool_fields),
};



/* ----- top-level mapping ----- */
static const cyaml_schema_field_t ppr_config_fields[] = {
    CYAML_FIELD_MAPPING ("app_settings",
        CYAML_FLAG_DEFAULT, ppr_config_t, app_settings, app_settings_fields),

    CYAML_FIELD_MAPPING ("thread_settings",
        CYAML_FLAG_DEFAULT, ppr_config_t, thread_settings, thread_settings_fields),

    CYAML_FIELD_SEQUENCE("port_settings",
        CYAML_FLAG_POINTER, ppr_config_t, port_settings, &port_entry_schema,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_SEQUENCE("mempool_settings",
        CYAML_FLAG_POINTER, ppr_config_t, mempool_settings, &mempool_entry_schema,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_MAPPING ("acl_table_settings",
        CYAML_FLAG_DEFAULT, ppr_config_t, acl_table_settings, acl_table_settings_fields),

    CYAML_FIELD_END
};

/* after */
const cyaml_schema_value_t ppr_config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, ppr_config_t, ppr_config_fields),
};