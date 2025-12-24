/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_log.h
Description: Logging in the WPR application uses a custom set of log types registered with DPDK's logging framework. This file contains the implementation for 
initializing and configuring these log types based on the application configuration. When logging in the application, the WPR_LOG macro defined in wpr_log.h 
should be used to ensure that logs are properly categorized and filtered according to the configured log levels.

*/
#ifndef WPR_LOG_H
#define WPR_LOG_H

#include <rte_log.h>
#include <stdatomic.h>

/* Extern declarations (defined once in wpr_log.c) */
extern int WPR_LOG_INIT;
extern int WPR_LOG_DP;
extern int WPR_LOG_FLOW;
extern int WPR_LOG_PORTS;
extern int WPR_LOG_PKTIO;
extern int WPR_LOG_CFG;
extern int WPR_LOG_STATS;
extern int WPR_LOG_RPC;
extern int WPR_LOG_CTL;
extern int WPR_LOG_LB;
extern int WPR_LOG_NETL;
extern int WPR_LOG_ACL;

typedef enum {
    LOG_STDOUT = 0,
    LOG_FILE   = 1,
} wpr_log_mode_t;


/* Initialize and register all logtypes */
int wpr_log_init_defaults(int log_level, int default_output, const char *log_dir);
int yaml_to_rte_log_level(int level);

/* Helper macro for conditional logging */
#define WPR_LOG(logtype, level, fmt, ...)                                       \
    do {                                                                        \
        if (rte_log_can_log((logtype), (level)))                                \
            rte_log((level), (logtype), fmt, ##__VA_ARGS__);                    \
    } while (0)

#ifndef WPR_DP_LOG_ENABLE
#define WPR_DP_LOG_ENABLE 0
#endif

#if WPR_DP_LOG_ENABLE
    #define WPR_DP_LOG(logtype, level, fmt, ...) \
        WPR_LOG(logtype, level, fmt, ##__VA_ARGS__)
#else
    // Completely compiled out – no function call, no branch.
    #define WPR_DP_LOG(logtype, level, fmt, ...) \
        do { } while (0)
#endif


#endif