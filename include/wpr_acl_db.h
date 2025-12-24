#ifndef WPR_ACL_DB_H
#define WPR_ACL_DB_H

#include "wpr_acl.h"

/* Struct to hold all IPV4 rules created by the user */
typedef struct wpr_acl_ip4_rule_db {
    wpr_acl_ip4_rule_cfg_t rules[WPR_ACL_MAX_RULES];
    bool                   used[WPR_ACL_MAX_RULES];
    uint32_t               active_count;   // number of used[] == true
    uint32_t               max_rule_id;    // highest index that is or has been used
    bool                   dirty;          // true if DB has uncommitted changes
} wpr_acl_ip4_rule_db_t;


/* Struct to hold all IPV6 rules created by the user */
typedef struct wpr_acl_ip6_rule_db {
    wpr_acl_ip6_rule_cfg_t rules[WPR_ACL_MAX_RULES];
    bool                   used[WPR_ACL_MAX_RULES];
    uint32_t               active_count;   // number of used[] == true
    uint32_t               max_rule_id;    // highest index that is or has been used
    bool                   dirty;          // true if DB has uncommitted changes
} wpr_acl_ip6_rule_db_t;


/* Struct to hold all L2 rules created by the user */
typedef struct wpr_acl_l2_rule_db {
    wpr_acl_l2_rule_cfg_t rules[WPR_ACL_MAX_RULES];
    bool                  used[WPR_ACL_MAX_RULES];
    uint32_t              active_count;
    uint32_t              max_rule_id;
    bool                  dirty;
} wpr_acl_l2_rule_db_t;

/* Wrapper struct to hold all rule database lists */
typedef struct wpr_acl_rule_db {
    wpr_acl_ip4_rule_db_t ip4;
    wpr_acl_ip6_rule_db_t ip6;
    wpr_acl_l2_rule_db_t  l2;
    bool                  dirty;
    // later: ipv6 db
} wpr_acl_rule_db_t;



/* proto functions */
//manage rule database
void wpr_acl_rule_db_init(wpr_acl_rule_db_t *db);

//add rules
int wpr_acl_db_add_ip4_rule(wpr_acl_rule_db_t *db, const wpr_acl_ip4_rule_cfg_t *spec, uint32_t *out_rule_id);
int wpr_acl_db_add_ip6_rule(wpr_acl_rule_db_t *db, const wpr_acl_ip6_rule_cfg_t *spec, uint32_t *out_rule_id);  
int wpr_acl_db_add_l2_rule(wpr_acl_rule_db_t *db, const wpr_acl_l2_rule_cfg_t *spec, uint32_t *out_rule_id);

//delete rules
int wpr_acl_db_del_ip4_rule(wpr_acl_rule_db_t *db, uint32_t rule_id);
int wpr_acl_db_del_ip6_rule(wpr_acl_rule_db_t *db, uint32_t rule_id);
int wpr_acl_db_del_l2_rule(wpr_acl_rule_db_t *db, uint32_t rule_id);

//update existing rules in the db 
int wpr_acl_db_update_ip4_rule(wpr_acl_rule_db_t *db, uint32_t rule_id, const wpr_acl_ip4_rule_cfg_t *spec);
int wpr_acl_db_update_ip6_rule(wpr_acl_rule_db_t *db, uint32_t rule_id, const wpr_acl_ip6_rule_cfg_t *spec);
int wpr_acl_db_update_l2_rule(wpr_acl_rule_db_t *db, uint32_t rule_id, const wpr_acl_l2_rule_cfg_t *spec);

int wpr_acl_db_get_highest_priority(wpr_acl_rule_db_t * db);
wpr_acl_l2_rule_cfg_t *wpr_acl_l2_get_highest_rule_by_ingress_port_id(wpr_acl_rule_db_t * db, uint16_t ingress_port_id);

//commit changes to runtime
int wpr_acl_db_commit(wpr_acl_runtime_t *rt, wpr_acl_rule_db_t *db);


//debug prints 
void wpr_acl_db_dump_status(wpr_acl_rule_db_t *db);

#endif /* WPR_ACL_DB_H__ */