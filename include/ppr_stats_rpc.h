#ifndef PPR_STATS_RPC_H
#define PPR_STATS_RPC_H

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

#include "ppr_app_defines.h"
#include "ppr_stats.h"
#include "ppr_log.h"



int ppr_cmd_mem_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_port_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_flowtable_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_worker_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);

#endif /* PPR_STATS_RPC_H */