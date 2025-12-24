/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_log.c
Description: Logging in the WPR application uses a custom set of log types registered with DPDK's logging framework. This file contains the implementation for 
initializing and configuring these log types based on the application configuration. When logging in the application, the WPR_LOG macro defined in wpr_log.h 
should be used to ensure that logs are properly categorized and filtered according to the configured log levels.

*/
#define _GNU_SOURCE

#include <rte_log.h>
#include <errno.h>

#include "wpr_log.h"

/* Define custom log types for wirepath switch */
int WPR_LOG_INIT, WPR_LOG_DP, WPR_LOG_FLOW, WPR_LOG_PORTS, WPR_LOG_CFG, WPR_LOG_STATS, WPR_LOG_RPC,WPR_LOG_PKTIO, WPR_LOG_CTL, WPR_LOG_LB, WPR_LOG_NETL, WPR_LOG_ACL;

/** 
* Initialize and register all logtypes
* @param cfg
*   Pointer to the application configuration    
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
*   - -ENOENT if log file cannot be opened
**/
int wpr_log_init_defaults(int log_level, int default_output, const char *log_dir){
    int rc=0; ;
    
    WPR_LOG_INIT  = rte_log_register("wpr.init");
    WPR_LOG_DP    = rte_log_register("wpr.dp");
    WPR_LOG_FLOW  = rte_log_register("wpr.flow");
    WPR_LOG_PORTS = rte_log_register("wpr.ports");
    WPR_LOG_CFG   = rte_log_register("wpr.cfg");
    WPR_LOG_STATS = rte_log_register("wpr.stats");
    WPR_LOG_PKTIO = rte_log_register("wpr.pktio");
    WPR_LOG_RPC   = rte_log_register("wpr.rpc");
    WPR_LOG_CTL   = rte_log_register("wpr.ctl");
    WPR_LOG_LB    = rte_log_register("wpr.lb");
    WPR_LOG_NETL  = rte_log_register("wpr.netl");
    WPR_LOG_ACL   = rte_log_register("wpr.acl");
    
    /* Sensible defaults; CLI can override with --log-level=... */
    rc = rte_log_set_level(WPR_LOG_INIT,    log_level);
    rc = rc + rte_log_set_level(WPR_LOG_DP,    log_level);
    rc = rc + rte_log_set_level(WPR_LOG_FLOW,  log_level);
    rc = rc + rte_log_set_level(WPR_LOG_PORTS, log_level);
    rc = rc + rte_log_set_level(WPR_LOG_CFG,   log_level);
    rc = rc + rte_log_set_level(WPR_LOG_STATS, log_level);
    rc = rc + rte_log_set_level(WPR_LOG_PKTIO, log_level);
    rc = rc + rte_log_set_level(WPR_LOG_RPC,   log_level);
    rc = rc + rte_log_set_level(WPR_LOG_CTL,   log_level);
    rc = rc + rte_log_set_level(WPR_LOG_LB,    log_level);
    rc = rc + rte_log_set_level(WPR_LOG_NETL,  log_level);
    rc = rc + rte_log_set_level(WPR_LOG_ACL,   log_level);
    if (rc < 0){
        return -EINVAL;
    }
    
    if (default_output == LOG_STDOUT){
        rte_openlog_stream(stdout);
    }
    else if (default_output == LOG_FILE && log_dir != NULL){
        char logfile[256];
        snprintf(logfile, sizeof(logfile), "%s/pcap_replay.log", log_dir);
        rc = rte_openlog_stream(fopen(logfile, "w"));
        if (rc < 0){
            return -ENOENT;
        }
    }
    else {
        return -EINVAL;
    }


    return 0;
}

/** 
* Convert yaml log level to rte log level
* @param level
*   yaml log level integer
* @return
*   corresponding rte log level integer
**/
int yaml_to_rte_log_level(int level)
{
    switch (level) {
        case 0: return RTE_LOGTYPE_EAL;
        case 1: return RTE_LOG_EMERG;
        case 2: return RTE_LOG_ALERT;
        case 3: return RTE_LOG_CRIT;
        case 4: return RTE_LOG_ERR;
        case 5: return RTE_LOG_WARNING;
        case 6: return RTE_LOG_NOTICE;
        case 7: return RTE_LOG_INFO;
        case 8: return RTE_LOG_DEBUG;
        default: return RTE_LOG_INFO;
    }
}