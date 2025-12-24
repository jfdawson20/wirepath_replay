#ifndef WPR_STATS_RPC_H
#define WPR_STATS_RPC_H

#include <unistd.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h> 
#include <unistd.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

#include "wpr_app_defines.h"
#include "wpr_stats.h"
#include "wpr_log.h"



int wpr_cmd_mem_stats(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_port_stats(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_flowtable_stats(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_worker_stats(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);

#endif /* WPR_STATS_RPC_H */