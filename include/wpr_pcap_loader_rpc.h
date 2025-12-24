#ifndef WPR_PCAP_LOADER_RPC_H
#define WPR_PCAP_LOADER_RPC_H


#include <jansson.h>

#include "wpr_pcap_loader.h"
#include "wpr_app_defines.h"

int wpr_get_loaded_pcaps_list(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_load_pcap_file(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_assign_port_slot(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);

#endif /* WPR_PCAP_LOADER_RPC_H */