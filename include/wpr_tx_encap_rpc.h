#ifndef WPR_TX_ENCAP_RPC_H
#define WPR_TX_ENCAP_RPC_H

#include <jansson.h>

#include "wpr_tx_encap.h"
#include "wpr_app_defines.h"   


/* RPC handlers */
int wpr_tx_encap_set(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_tx_encap_clear(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_tx_encap_get(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);

#endif /* WPR_TX_ENCAP_RPC_H */