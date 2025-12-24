
#include "wpr_acl_db.h"


/** 
* Initialize an ACL rule database structure.
* @param db
*   Pointer to ACL rule database structure to initialize.   
**/
void wpr_acl_rule_db_init(wpr_acl_rule_db_t *db)
{
    memset(db, 0, sizeof(*db));

    //for clarity
    db->dirty = false;

}


/** 
* Add an IPv4 rule to the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param spec
*   Pointer to IPv4 rule configuration structure.
* @param out_rule_id  
*   returns assigned rule ID if successful.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_add_ip4_rule(wpr_acl_rule_db_t *db,const wpr_acl_ip4_rule_cfg_t *spec, uint32_t *out_rule_id)
{
    if (!db || !spec )
        return -EINVAL;

    wpr_acl_ip4_rule_db_t *ip4 = &db->ip4;

    // find a free slot
    uint32_t idx;
    for (idx = 0; idx < WPR_ACL_MAX_RULES; idx++) {
        if (!ip4->used[idx])
            break;
    }
    if (idx == WPR_ACL_MAX_RULES)
        return -ENOSPC;

    // copy spec into DB slot
    wpr_acl_ip4_rule_cfg_t *dst = &ip4->rules[idx];
    *dst = *spec;
    dst->rule_id = idx;          // enforce invariant: rule_id == array index

    ip4->used[idx] = true;
    ip4->active_count++;
    if (idx > ip4->max_rule_id)
        ip4->max_rule_id = idx;

    ip4->dirty = true;
    db->dirty  = true;
    if(out_rule_id)
        *out_rule_id = idx;
    return 0;
}

/** 
* Add an IPv6 rule to the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param spec
*   Pointer to IPv6 rule configuration structure.
* @param out_rule_id  
*   returns assigned rule ID if successful.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_add_ip6_rule(wpr_acl_rule_db_t *db,const wpr_acl_ip6_rule_cfg_t *spec, uint32_t *out_rule_id)
{
    if (!db || !spec ){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "wpr_acl_db_add_ip6_rule: invalid parameters\n");
        return -EINVAL;
    }

    wpr_acl_ip6_rule_db_t *ip6 = &db->ip6;

    // find a free slot
    uint32_t idx;
    for (idx = 0; idx < WPR_ACL_MAX_RULES; idx++) {
        if (!ip6->used[idx]){
            break;
        }
    }
    if (idx == WPR_ACL_MAX_RULES){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "wpr_acl_db_add_ip6_rule: no free slots available\n");
        return -ENOSPC;
    }

    // copy spec into DB slot
    wpr_acl_ip6_rule_cfg_t *dst = &ip6->rules[idx];
    *dst = *spec;
    dst->rule_id = idx;          // enforce invariant: rule_id == array index

    ip6->used[idx] = true;
    ip6->active_count++;
    if (idx > ip6->max_rule_id)
        ip6->max_rule_id = idx;

    ip6->dirty = true;
    db->dirty  = true;

    if(out_rule_id)
        *out_rule_id = idx;
    return 0;
}


/** 
* Add an L2 rule to the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param spec
*   Pointer to L2 rule configuration structure.
* @param out_rule_id  
*   returns assigned rule ID if successful.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_add_l2_rule(wpr_acl_rule_db_t *db,const wpr_acl_l2_rule_cfg_t *spec,uint32_t *out_rule_id)
{
    if (!db || !spec)
        return -EINVAL;

    wpr_acl_l2_rule_db_t *l2 = &db->l2;

    // find a free slot
    uint32_t idx;
    for (idx = 0; idx < WPR_ACL_MAX_RULES; idx++) {
        if (!l2->used[idx])
            break;
    }
    if (idx == WPR_ACL_MAX_RULES)
        return -ENOSPC;

    // copy spec into DB slot
    wpr_acl_l2_rule_cfg_t *dst = &l2->rules[idx];
    *dst = *spec;
    dst->rule_id = idx;          // enforce invariant: rule_id == array index

    l2->used[idx] = true;
    l2->active_count++;
    if (idx > l2->max_rule_id)
        l2->max_rule_id = idx;

    l2->dirty = true;
    db->dirty  = true;
    if(out_rule_id)
        *out_rule_id = idx;
    return 0;
}

/** 
* Delete an IPv4 rule from the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param rule_id
*   Rule ID of the rule to delete.
* @return
*   0 on success, negative errno on failure.    
**/
int wpr_acl_db_del_ip4_rule(wpr_acl_rule_db_t *db, uint32_t rule_id)
{
    if (!db)
        return -EINVAL;

    wpr_acl_ip4_rule_db_t *ip4 = &db->ip4;

    if (rule_id >= WPR_ACL_MAX_RULES || !ip4->used[rule_id])
        return -ENOENT;

    ip4->used[rule_id] = false;
    if (ip4->active_count > 0)
        ip4->active_count--;

    // optional: you can also memset the cfg to 0
    memset(&ip4->rules[rule_id], 0, sizeof(ip4->rules[rule_id]));

    // You may or may not shrink max_rule_id here; not required,
    // but you can scan backwards if you want:
    while (ip4->max_rule_id > 0 && !ip4->used[ip4->max_rule_id])
        ip4->max_rule_id--;

    ip4->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Delete an IPv6 rule from the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param rule_id
*   Rule ID of the rule to delete.
* @return
*   0 on success, negative errno on failure.    
**/
int wpr_acl_db_del_ip6_rule(wpr_acl_rule_db_t *db, uint32_t rule_id)
{
    if (!db)
        return -EINVAL;

    wpr_acl_ip6_rule_db_t *ip6 = &db->ip6;

    if (rule_id >= WPR_ACL_MAX_RULES || !ip6->used[rule_id])
        return -ENOENT;

    ip6->used[rule_id] = false;
    if (ip6->active_count > 0)
        ip6->active_count--;

    // optional: you can also memset the cfg to 0
    memset(&ip6->rules[rule_id], 0, sizeof(ip6->rules[rule_id]));

    // You may or may not shrink max_rule_id here; not required,
    // but you can scan backwards if you want:
    while (ip6->max_rule_id > 0 && !ip6->used[ip6->max_rule_id])
        ip6->max_rule_id--;

    ip6->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Delete an L2 rule from the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param rule_id
*   Rule ID of the rule to delete.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_del_l2_rule(wpr_acl_rule_db_t *db, uint32_t rule_id)
{
    if (!db)
        return -EINVAL;

    wpr_acl_l2_rule_db_t *l2 = &db->l2;

    if (rule_id >= WPR_ACL_MAX_RULES || !l2->used[rule_id])
        return -ENOENT;

    l2->used[rule_id] = false;
    if (l2->active_count > 0)
        l2->active_count--;

    // optional: you can also memset the cfg to 0
    memset(&l2->rules[rule_id], 0, sizeof(l2->rules[rule_id]));

    // You may or may not shrink max_rule_id here; not required,
    // but you can scan backwards if you want:
    while (l2->max_rule_id > 0 && !l2->used[l2->max_rule_id])
        l2->max_rule_id--;

    l2->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Update an existing IPv4 rule in the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param rule_id
*   Rule ID of the rule to update.
* @param spec
*   Pointer to new IPv4 rule configuration structure.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_update_ip4_rule(wpr_acl_rule_db_t *db,uint32_t rule_id,const wpr_acl_ip4_rule_cfg_t *spec)
{
    if (!db || !spec)
        return -EINVAL;

    wpr_acl_ip4_rule_db_t *ip4 = &db->ip4;
    if (rule_id >= WPR_ACL_MAX_RULES || !ip4->used[rule_id])
        return -ENOENT;

    wpr_acl_ip4_rule_cfg_t *dst = &ip4->rules[rule_id];
    *dst = *spec;
    dst->rule_id = rule_id;  // preserve invariant

    ip4->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Update an existing IPv6 rule in the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @param rule_id
*   Rule ID of the rule to update.
* @param spec
*   Pointer to new IPv6 rule configuration structure.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_update_ip6_rule(wpr_acl_rule_db_t *db,uint32_t rule_id,const wpr_acl_ip6_rule_cfg_t *spec)
{
    if (!db || !spec)
        return -EINVAL;

    wpr_acl_ip6_rule_db_t *ip6 = &db->ip6;
    if (rule_id >= WPR_ACL_MAX_RULES || !ip6->used[rule_id])
        return -ENOENT;

    wpr_acl_ip6_rule_cfg_t *dst = &ip6->rules[rule_id];
    *dst = *spec;
    dst->rule_id = rule_id;  // preserve invariant

    ip6->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Update an existing L2 rule in the ACL rule database.
* @param db
*   Pointer to ACL rule database.   
* @param rule_id
*   Rule ID of the rule to update.
* @param spec
*   Pointer to new L2 rule configuration structure.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_db_update_l2_rule(wpr_acl_rule_db_t *db,uint32_t rule_id,const wpr_acl_l2_rule_cfg_t *spec)
{
    if (!db || !spec)
        return -EINVAL;

    wpr_acl_l2_rule_db_t *l2 = &db->l2;
    if (rule_id >= WPR_ACL_MAX_RULES || !l2->used[rule_id])
        return -ENOENT;

    wpr_acl_l2_rule_cfg_t *dst = &l2->rules[rule_id];
    *dst = *spec;
    dst->rule_id = rule_id;  // preserve invariant

    l2->dirty = true;
    db->dirty  = true;
    return 0;
}

/** 
* Get the highest priority value among all rules in the ACL rule database.
* @param db
*   Pointer to ACL rule database.
* @return
*   Highest priority value on success, negative errno on failure.
**/
int wpr_acl_db_get_highest_priority(wpr_acl_rule_db_t * db){

    if(!db){
        return -EINVAL;
    }

    int highest_priority = -1;

    //check IPv4 rules
    wpr_acl_ip4_rule_db_t * ip4_db = &db->ip4;
    for(unsigned int i=0; i < WPR_ACL_MAX_RULES; i++){
        if(ip4_db->used[i]){
            wpr_acl_ip4_rule_cfg_t * rule_cfg = &ip4_db->rules[i];
            if(rule_cfg->priority > highest_priority){
                highest_priority = rule_cfg->priority;
            }
        }
    }

    //check IPv6 rules
    wpr_acl_ip6_rule_db_t * ip6_db = &db->ip6;
    for(unsigned int i=0; i < WPR_ACL_MAX_RULES; i++){
        if(ip6_db->used[i]){
            wpr_acl_ip6_rule_cfg_t * rule_cfg = &ip6_db->rules[i];
            if(rule_cfg->priority > highest_priority){
                highest_priority = rule_cfg->priority;
            }
        }
    }

    //check L2 rules
    wpr_acl_l2_rule_db_t * l2_db = &db->l2;
    for(unsigned int i=0; i < WPR_ACL_MAX_RULES; i++){
        if(l2_db->used[i]){
            wpr_acl_l2_rule_cfg_t * rule_cfg = &l2_db->rules[i];
            if(rule_cfg->priority > highest_priority){
                highest_priority = rule_cfg->priority;
            }
        }
    }

    return highest_priority;

}

/** 
* if a rule exists that matches the given ingress port ID, return the highest priority rule cfg
* @param db
*   Pointer to ACL rule database.
* @param ingress_port_id
*   Ingress port ID to match against.
* @return
*   Pointer to highest priority matching L2 rule cfg on success, negative errno on failure.
**/
wpr_acl_l2_rule_cfg_t *wpr_acl_l2_get_highest_rule_by_ingress_port_id(wpr_acl_rule_db_t * db, uint16_t ingress_port_id){

    if(!db){
        return NULL;
    }
    wpr_acl_l2_rule_cfg_t *out_rule_cfg = NULL; 
    
    wpr_acl_l2_rule_db_t * l2_db = &db->l2;

    int hightest_priority = -1; 
    for(unsigned int i=0; i < WPR_ACL_MAX_RULES; i++){
        if(l2_db->used[i]){
            wpr_acl_l2_rule_cfg_t * rule_cfg = &l2_db->rules[i];
            if(rule_cfg->in_port_lo <= ingress_port_id && rule_cfg->in_port_hi >= ingress_port_id){
                //match
                if(rule_cfg->priority > hightest_priority){
                    hightest_priority = rule_cfg->priority;
                    out_rule_cfg = rule_cfg;
                }
            }
        }
    }

    return out_rule_cfg;
}

/** 
* Commit all db rules into the ACL runtime.
* @param rt
*   Pointer to ACL runtime structure.
* @param db
*   Pointer to ACL rule database.
* @param max_ip4_rules
*   Maximum number of IPv4 rules to allocate space for.
* @param max_l2_rules
*   Maximum number of L2 rules to allocate space for.
* @return
*   0 on success, negative errno on failure.    
**/
int wpr_acl_db_commit(wpr_acl_runtime_t *rt, wpr_acl_rule_db_t *db)
{
    uint32_t max_ip4_rules = db->ip4.active_count;
    uint32_t max_ip6_rules = db->ip6.active_count;
    uint32_t max_l2_rules  = db->l2.active_count;

    if (!rt || !db){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "wpr_acl_db_commit: invalid parameters\n");
        return -EINVAL;
    }

    // If nothing changed, skip rebuild
    if (!db->ip4.dirty && !db->ip6.dirty && !db->l2.dirty){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO,
                "wpr_acl_db_commit: no changes detected, skipping rebuild\n");
        return 0;
    }

    wpr_acl_build_ctx_t bld;
    int rc = wpr_acl_build_begin(&bld, rt, max_ip4_rules, max_ip6_rules, max_l2_rules);
    if (rc < 0){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "wpr_acl_build_begin failed rc=%d\n", rc);
        return rc;
    }

    // Re-add all active IPv4 rules
    if (db->ip4.active_count > 0) {
        wpr_acl_ip4_rule_db_t *ip4db = &db->ip4;
        for (uint32_t i = 0; i <= ip4db->max_rule_id; i++) {
            if (!ip4db->used[i])
                continue;

            wpr_acl_ip4_rule_cfg_t *cfg = &ip4db->rules[i];
            // cfg->rule_id is already i
            rc = wpr_acl_build_add_ip4_rule(&bld, cfg);
            if (rc < 0) {
                WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                        "wpr_acl_build_add_ip4_rule failed rc=%d\n", rc);
                wpr_acl_build_abort(&bld);
                return rc;
            }
        }
    }

    if (db->ip6.active_count > 0) {
        wpr_acl_ip6_rule_db_t *ip6db = &db->ip6;
        for (uint32_t i = 0; i <= ip6db->max_rule_id; i++) {
            if (!ip6db->used[i])
                continue;

            wpr_acl_ip6_rule_cfg_t *cfg = &ip6db->rules[i];
            // cfg->rule_id is already i
            rc = wpr_acl_build_add_ip6_rule(&bld, cfg);
            if (rc < 0) {
                WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                        "wpr_acl_build_add_ip6_rule failed rc=%d\n", rc);
                wpr_acl_build_abort(&bld);
                return rc;
            }
        }
    }

    // Re-add all active L2 rules
    if (db->l2.active_count > 0) {
        wpr_acl_l2_rule_db_t *l2db = &db->l2;
        for (uint32_t i = 0; i <= l2db->max_rule_id; i++) {
            if (!l2db->used[i])
                continue;

            wpr_acl_l2_rule_cfg_t *cfg = &l2db->rules[i];
            rc = wpr_acl_build_add_l2_rule(&bld, cfg);
            if (rc < 0) {
                WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                        "wpr_acl_build_add_l2_rule failed rc=%d\n", rc);
                wpr_acl_build_abort(&bld);
                return rc;
            }
        }
    }

    // Swap into runtime (QSBR handles retire)
    rc = wpr_acl_build_commit(rt, &bld);
    if (rc < 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "wpr_acl_build_commit failed rc=%d\n", rc);
        wpr_acl_build_abort(&bld);
        return rc;
    }

    //rte_acl_dump(rt->ip4_acl_curr);
    //rte_acl_dump(rt->ip6_acl_curr);
    //rte_acl_dump(rt->l2_acl_curr);
    // Mark DB as clean
    db->ip4.dirty = false;
    db->ip6.dirty = false;
    db->l2.dirty  = false;
    db->dirty     = false;
    
    return 0;
}

/* --------------------------- Debug Prints -------------------------------------  */

void wpr_acl_db_dump_status(wpr_acl_rule_db_t *db)
{
    if (!db)
        return;

    wpr_acl_ip4_rule_db_t *ip4 = &db->ip4;
    wpr_acl_ip6_rule_db_t *ip6 = &db->ip6;
    wpr_acl_l2_rule_db_t  *l2  = &db->l2;

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO,
            "ACL DB Status: IP4 active=%u max_id=%u dirty=%s\n",
            ip4->active_count,
            ip4->max_rule_id,
            ip4->dirty ? "yes" : "no");

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO,
            "ACL DB Status: IP6 active=%u max_id=%u dirty=%s\n",
            ip6->active_count,
            ip6->max_rule_id,
            ip6->dirty ? "yes" : "no");

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO,
            "ACL DB Status: L2  active=%u max_id=%u dirty=%s\n",
            l2->active_count,
            l2->max_rule_id,
            l2->dirty ? "yes" : "no");

    //dump all ipv4 rules 
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO, "\nACL DB IPv4 Rules:\n");
    for (unsigned int i=0; i <= ip4->max_rule_id; i++){
        if(ip4->used[i]){
            wpr_acl_print_ip4_rule(&ip4->rules[i]);
        }
    }

    //dump all ipv6 rules
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO, "\nACL DB IPv6 Rules:\n");
    for (unsigned int i=0; i <= ip6->max_rule_id; i++){
        if(ip6->used[i]){
            wpr_acl_print_ip6_rule(&ip6->rules[i]);
        }
    }

    //dump all l2 rules
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO, "\nACL DB L2 Rules:\n");
    for (unsigned int i=0; i <= l2->max_rule_id; i++){
        if(l2->used[i]){
            wpr_acl_print_l2_rule(&l2->rules[i]);
        }
    }
}   