#ifndef PPR_ACL_DB_H
#define PPR_ACL_DB_H

#include "ppr_acl.h"

/* Struct to hold all IPV4 rules created by the user */
typedef struct ppr_acl_ip4_rule_db {
    ppr_acl_ip4_rule_cfg_t rules[PPR_ACL_MAX_RULES];
    bool                   used[PPR_ACL_MAX_RULES];
    uint32_t               active_count;   // number of used[] == true
    uint32_t               max_rule_id;    // highest index that is or has been used
    bool                   dirty;          // true if DB has uncommitted changes
} ppr_acl_ip4_rule_db_t;


/* Struct to hold all IPV6 rules created by the user */
typedef struct ppr_acl_ip6_rule_db {
    ppr_acl_ip6_rule_cfg_t rules[PPR_ACL_MAX_RULES];
    bool                   used[PPR_ACL_MAX_RULES];
    uint32_t               active_count;   // number of used[] == true
    uint32_t               max_rule_id;    // highest index that is or has been used
    bool                   dirty;          // true if DB has uncommitted changes
} ppr_acl_ip6_rule_db_t;


/* Struct to hold all L2 rules created by the user */
typedef struct ppr_acl_l2_rule_db {
    ppr_acl_l2_rule_cfg_t rules[PPR_ACL_MAX_RULES];
    bool                  used[PPR_ACL_MAX_RULES];
    uint32_t              active_count;
    uint32_t              max_rule_id;
    bool                  dirty;
} ppr_acl_l2_rule_db_t;

/* Wrapper struct to hold all rule database lists */
typedef struct ppr_acl_rule_db {
    ppr_acl_ip4_rule_db_t ip4;
    ppr_acl_ip6_rule_db_t ip6;
    ppr_acl_l2_rule_db_t  l2;
    bool                  dirty;
    // later: ipv6 db
} ppr_acl_rule_db_t;



/* proto functions */
//manage rule database
void ppr_acl_rule_db_init(ppr_acl_rule_db_t *db);

//add rules
int ppr_acl_db_add_ip4_rule(ppr_acl_rule_db_t *db, const ppr_acl_ip4_rule_cfg_t *spec, uint32_t *out_rule_id);
int ppr_acl_db_add_ip6_rule(ppr_acl_rule_db_t *db, const ppr_acl_ip6_rule_cfg_t *spec, uint32_t *out_rule_id);  
int ppr_acl_db_add_l2_rule(ppr_acl_rule_db_t *db, const ppr_acl_l2_rule_cfg_t *spec, uint32_t *out_rule_id);

//delete rules
int ppr_acl_db_del_ip4_rule(ppr_acl_rule_db_t *db, uint32_t rule_id);
int ppr_acl_db_del_ip6_rule(ppr_acl_rule_db_t *db, uint32_t rule_id);
int ppr_acl_db_del_l2_rule(ppr_acl_rule_db_t *db, uint32_t rule_id);

//update existing rules in the db 
int ppr_acl_db_update_ip4_rule(ppr_acl_rule_db_t *db, uint32_t rule_id, const ppr_acl_ip4_rule_cfg_t *spec);
int ppr_acl_db_update_ip6_rule(ppr_acl_rule_db_t *db, uint32_t rule_id, const ppr_acl_ip6_rule_cfg_t *spec);
int ppr_acl_db_update_l2_rule(ppr_acl_rule_db_t *db, uint32_t rule_id, const ppr_acl_l2_rule_cfg_t *spec);

int ppr_acl_db_get_highest_priority(ppr_acl_rule_db_t * db);
ppr_acl_l2_rule_cfg_t *ppr_acl_l2_get_highest_rule_by_ingress_port_id(ppr_acl_rule_db_t * db, uint16_t ingress_port_id);

//commit changes to runtime
int ppr_acl_db_commit(ppr_acl_runtime_t *rt, ppr_acl_rule_db_t *db);


//debug prints 
void ppr_acl_db_dump_status(ppr_acl_rule_db_t *db);

#endif /* PPR_ACL_DB_H__ */