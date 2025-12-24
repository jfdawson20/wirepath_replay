#ifndef WPR_ACL_API_H
#define WPR_ACL_API_H

#include <jansson.h>
#include "wpr_acl.h"
#include "wpr_acl_db.h"
#include "wpr_log.h"
#include "wpr_app_defines.h"

/* Control RPC API Functions */
int wpr_cmd_get_acl_db(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_add_acl_rule(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_update_acl_rule(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_delete_acl_rule(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_check_acl_status(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);
int wpr_cmd_acl_db_commit(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args);

#endif /* WPR_ACL_API_H */

