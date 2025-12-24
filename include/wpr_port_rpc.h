#ifndef WPR_PORT_RPC_H
#define WPR_PORT_RPC_H

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
#include "wpr_ports.h"
#include "wpr_log.h"

int wpr_cmd_get_port_list(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_port_tx_ctl(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_set_port_stream_vcs(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);

#endif // WPR_PORT_RPC_H