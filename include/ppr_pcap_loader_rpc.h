#ifndef PPR_PCAP_LOADER_RPC_H
#define PPR_PCAP_LOADER_RPC_H

#include "ppr_pcap_loader.h"
#include "ppr_app_defines.h"

int ppr_load_pcap_file(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);

#endif /* PPR_PCAP_LOADER_RPC_H */