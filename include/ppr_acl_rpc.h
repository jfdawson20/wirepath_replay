#ifndef PPR_ACL_API_H
#define PPR_ACL_API_H

#include <jansson.h>
#include "ppr_acl.h"
#include "ppr_acl_db.h"
#include "ppr_log.h"
#include "ppr_app_defines.h"

/* Control RPC API Functions */
int ppr_cmd_get_acl_db(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_add_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_update_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_delete_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_check_acl_status(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_cmd_acl_db_commit(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);

#endif /* PPR_ACL_API_H */

