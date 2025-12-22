#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>

#include "ppr_acl.h"
#include "ppr_acl_rpc.h"
#include "ppr_helpers.h"
#include "ppr_ports.h"
#include "ppr_app_defines.h"

/* --------------------------- Static / Internal JSON <> Structs Helpers ----------------------------- */
/** 
* Fetch a required integer field from a JSON object.
* @param obj
*   Pointer to JSON object.
* @param key
*   Key name of the field to fetch.
* @param val_out
*   Pointer to output integer variable.
* @return
*   0 on success, negative errno on failure.
**/
static int json_get_required_int(const json_t *obj, const char *key, int64_t *val_out)
{
    json_t *v = json_object_get(obj, key);
    if (!v || !json_is_integer(v))
        return -EINVAL;
    *val_out = json_integer_value(v);
    return 0;
}

/** 
* Fetch a required string field from a JSON object.
* @param obj
*   Pointer to JSON object.
* @param key
*   Key name of the field to fetch.
* @param str_out
*   Pointer to output string variable.
* @return
*   0 on success, negative errno on failure.
**/
static int json_get_required_string(const json_t *obj, const char *key, const char **str_out)
{
    json_t *v = json_object_get(obj, key);
    if (!v || !json_is_string(v))
        return -EINVAL;
    *str_out = json_string_value(v);
    return 0;
}




/**
* Format a MAC address into a string.
* Example output: "01:23:45:67:89:ab"
* @param mac
*   Pointer to rte_ether_addr structure.
* @param buf
*   Buffer to write the formatted string.
* @param buf_len
*   Length of the buffer.
**/
static void format_mac(const struct rte_ether_addr *mac, char *buf, size_t buf_len)
{
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
             mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

//parse a list of port names comma separated, return global index range
static int parse_input_port_list(const char *s ,ppr_ports_t *global_port_list, uint16_t *lo_out, uint16_t *hi_out)
{
    /* Missing or empty -> wildcard [0,65535] */
    if (!s || !*s ||
        !strcasecmp(s, "any") ||
        !strcmp(s, "*")) {
        *lo_out = 0;
        *hi_out = global_port_list->num_ports - 1;
        return 0;
    }    

    /* If it contains a colon, treat as "lo:hi" */
    const char *colon = strchr(s, ':');
    char lo[64];
    char hi[64];

    if (colon) {
        if (sscanf(s, "%63[^:]:%63s", lo, hi) != 2)
            return -EINVAL;

        ppr_port_entry_t *port_lo = ppr_find_port_byname(global_port_list, lo);
        ppr_port_entry_t *port_hi = ppr_find_port_byname(global_port_list, hi);
        if (!port_lo || !port_hi){
            return -EINVAL;
        }
        *lo_out = port_lo->port_id;
        *hi_out = port_hi->port_id;
        PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO, "Parsed port list '%s' to range [%u,%u]\n", s, *lo_out, *hi_out);
        return 0;
    }

    const char *dash  = strchr(s, '-');
    if(dash){
        if (sscanf(s, "%63[^-]-%63s", lo, hi) != 2)
            return -EINVAL;

        ppr_port_entry_t *port_lo = ppr_find_port_byname(global_port_list, lo);
        ppr_port_entry_t *port_hi = ppr_find_port_byname(global_port_list, hi);
        if (!port_lo || !port_hi){
            return -EINVAL;
        }
        *lo_out = port_lo->port_id;
        *hi_out = port_hi->port_id;
        PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO, "Parsed port list '%s' to range [%u,%u]\n", s, *lo_out, *hi_out);
        return 0;      
    }

    /* Otherwise treat as single port "p" → [p,p] */
    if (sscanf(s, "%63s", lo) != 1)
        return -EINVAL;

    ppr_port_entry_t *port_lo = ppr_find_port_byname(global_port_list, lo);
    if (!port_lo){
        return -EINVAL;
    }    
    *lo_out = port_lo->port_id;
    *hi_out = port_lo->port_id;
    PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO, "Parsed port list '%s' to range [%u,%u]\n", s, *lo_out, *hi_out);
    return 0;
}

static int parse_port_range(const char *s, uint16_t *lo_out, uint16_t *hi_out)
{
    unsigned int lo, hi;

    if (!lo_out || !hi_out)
        return -EINVAL;

    /* Missing or empty -> wildcard [0,65535] */
    if (!s || !*s ||
        !strcasecmp(s, "any") ||
        !strcmp(s, "*")) {
        *lo_out = 0;
        *hi_out = 65535;
        return 0;
    }

    /* If it contains a colon, treat as "lo:hi" */
    const char *colon = strchr(s, ':');
    if (colon) {
        if (sscanf(s, "%u:%u", &lo, &hi) != 2)
            return -EINVAL;
        if (lo > 65535 || hi > 65535)
            return -EINVAL;
        if (lo > hi)
            return -EINVAL;   /* or swap if you prefer being forgiving */
        *lo_out = (uint16_t)lo;
        *hi_out = (uint16_t)hi;
        return 0;
    }

    const char *dash  = strchr(s, '-');
    if(dash){
        if (sscanf(s, "%u-%u", &lo, &hi) != 2)
            return -EINVAL;
        if (lo > 65535 || hi > 65535)
            return -EINVAL;
        if (lo > hi)
            return -EINVAL;   /* or swap if you prefer being forgiving */
        *lo_out = (uint16_t)lo;
        *hi_out = (uint16_t)hi;
        return 0;        
    }

    /* Otherwise treat as single port "p" → [p,p] */
    if (sscanf(s, "%u", &lo) != 1 || lo > 65535)
        return -EINVAL;

    *lo_out = (uint16_t)lo;
    *hi_out = (uint16_t)lo;
    return 0;
}

static int parse_tenant_range(const char *s, uint32_t *lo_out, uint32_t *hi_out)
{
    uint32_t lo, hi;

    if (!lo_out || !hi_out)
        return -EINVAL;

    /* Missing or empty -> wildcard [0,4294967295] */
    if (!s || !*s || !strcasecmp(s, "any") || !strcmp(s, "*")) {
        *lo_out = 0;
        *hi_out = 4294967295;
        return 0;
    }

    /* If it contains a colon, treat as "lo:hi" */
    const char *colon = strchr(s, ':');
    if (colon) {
        if (sscanf(s, "%u:%u", &lo, &hi) != 2)
            return -EINVAL;
        if (lo > 4294967294 || hi > 4294967294)
            return -EINVAL;
        if (lo > hi)
            return -EINVAL;   /* or swap if you prefer being forgiving */
        *lo_out = (uint16_t)lo;
        *hi_out = (uint16_t)hi;
        return 0;
    }

    const char *dash  = strchr(s, '-');
    if(dash){
        if (sscanf(s, "%u-%u", &lo, &hi) != 2)
            return -EINVAL;
        if (lo > 4294967294 || hi > 4294967294)
            return -EINVAL;
        if (lo > hi)
            return -EINVAL;   /* or swap if you prefer being forgiving */
        *lo_out = (uint16_t)lo;
        *hi_out = (uint16_t)hi;
        return 0;        
    }

    /* Otherwise treat as single port "p" → [p,p] */
    if (sscanf(s, "%u", &lo) != 1 || lo > 4294967294)
        return -EINVAL;

    *lo_out = (uint16_t)lo;
    *hi_out = (uint16_t)lo;
    return 0;
}


static json_t *ppr_policy_action_to_json(ppr_ports_t *global_port_list, const ppr_policy_action_t *action)
{
    if (!action)
        return NULL;

    json_t *obj = json_object();
    if (!obj)
        return NULL;

    /* we don’t encode hit (runtime only) */
    json_object_set_new(obj, "default_policy",
                        json_string(ppr_flow_action_kind_to_str(action->default_policy)));


    return obj;
}

static int ppr_acl_action_from_json(const json_t *obj, ppr_ports_t *global_port_list,ppr_policy_action_t *out)
{
    if (!obj || !json_is_object(obj) || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));

    int64_t v;
    if (json_get_required_int(obj, "default_policy", &v) < 0)
        return -EINVAL;
    out->default_policy = (ppr_flow_action_kind_t)v;




    out->hit = false; /* config path: not a runtime match */

    return 0;
}

/* ---------- IPv4 rule <-> JSON ---------- */

static json_t *ppr_acl_ip4_rule_to_json(ppr_acl_runtime_t *acl_rt, ppr_ports_t *global_port_list, 
                                        const ppr_acl_ip4_rule_cfg_t *cfg, unsigned int rule_index)
{
    if (!cfg || !acl_rt || !global_port_list)
        return NULL;

    json_t *obj = json_object();
    if (!obj)
        return NULL;

    //get acl rule stats
    ppr_acl_rule_db_stats_t *acl_stats = atomic_load_explicit(&acl_rt->global_stats_curr, memory_order_acquire); 
    if (acl_stats){
        ppr_acl_rule_stats_t rule_stats = acl_stats->ip4[rule_index];
        uint64_t total_flows = atomic_load_explicit(&rule_stats.total_flows, memory_order_relaxed);
        uint64_t active_flows = atomic_load_explicit(&rule_stats.active_flows, memory_order_relaxed);

        json_object_set_new(obj, "total_flows", json_integer(total_flows));
        json_object_set_new(obj, "active_flows", json_integer(active_flows));
    }
    else {
        json_object_set_new(obj, "total_flows", json_integer(0));
        json_object_set_new(obj, "active_flows", json_integer(0));
    }

    

    char tenant_id_buf[64];
    snprintf(tenant_id_buf, sizeof(tenant_id_buf), "%u:%u", cfg->tenant_id_lo, cfg->tenant_id_hi);
    json_object_set_new(obj, "tenant_ids", json_string(tenant_id_buf));
    json_object_set_new(obj, "src_prefix", json_integer(cfg->src_prefix));
    json_object_set_new(obj, "dst_prefix", json_integer(cfg->dst_prefix));

    /* src / dst IP as dotted strings */
    char buf[INET_ADDRSTRLEN];
    struct in_addr ina;

    ina.s_addr = htonl(cfg->src_ip);
    if (!inet_ntop(AF_INET, &ina, buf, sizeof(buf))) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "src", json_string(buf));

    ina.s_addr = htonl(cfg->dst_ip);
    if (!inet_ntop(AF_INET, &ina, buf, sizeof(buf))) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "dst", json_string(buf));

    /* ports & proto */
    char src_port_buf[64];
    char dst_port_buf[64];

    snprintf(src_port_buf, sizeof(src_port_buf), "%u:%u", cfg->src_port_lo, cfg->src_port_hi);
    snprintf(dst_port_buf, sizeof(dst_port_buf), "%u:%u", cfg->dst_port_lo, cfg->dst_port_hi);
    json_object_set_new(obj, "src_ports", json_string(src_port_buf));
    json_object_set_new(obj, "dst_ports", json_string(dst_port_buf));
    json_object_set_new(obj, "proto",        json_integer(cfg->proto));

    /* ingress port range */
    ppr_port_entry_t *port_entry_lo = ppr_find_port_byid(global_port_list, cfg->in_port_lo);
    ppr_port_entry_t *port_entry_hi = ppr_find_port_byid(global_port_list, cfg->in_port_hi);
    if( port_entry_lo != NULL && port_entry_hi != NULL){
        char in_port_buf[128];
        snprintf(in_port_buf, sizeof(in_port_buf), "%s-%s", port_entry_lo->name, port_entry_hi->name);
        json_object_set_new(obj, "in_ports", json_string(in_port_buf));
    }
    else {
        json_object_set_new(obj, "in_ports", json_string("any"));
    }

    json_object_set_new(obj, "priority", json_integer(cfg->priority));
    json_object_set_new(obj, "rule_id",  json_integer(cfg->rule_id));


    /* action */
    json_t *act = ppr_policy_action_to_json(global_port_list, &cfg->action);
    if (!act) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "action", act);

    return obj;
}

static int ppr_acl_ip4_rule_from_json(const json_t *obj, ppr_ports_t *global_port_list, ppr_acl_ip4_rule_cfg_t *out)
{
    if (!obj || !json_is_object(obj) || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));

    int64_t v;
    const char *s;

    /* tenant ID */
    if(json_get_required_string(obj, "tenant_ids", &s) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else {
        uint32_t ten_lo, ten_hi;
        if(parse_tenant_range(s, &ten_lo, &ten_hi) < 0){
            out->tenant_id_lo = 0;
            out->tenant_id_hi = 0xFFFFFFFF;
        }
        else{
            out->tenant_id_lo = ten_lo;
            out->tenant_id_hi = ten_hi;
        }
    }

    /* src/dst addresses */
    struct in_addr ina;
    //if no address default to 0.0.0.0
    if (json_get_required_string(obj, "src", &s) < 0){
        if (inet_pton(AF_INET, "0.0.0.0", &ina) != 1)
            return -EINVAL;
        out->src_ip = rte_be_to_cpu_32(ina.s_addr);
    }
    else {
        if (inet_pton(AF_INET, s, &ina) != 1)
            return -EINVAL;
        out->src_ip = rte_be_to_cpu_32(ina.s_addr);
    }

    //if no address default to 0.0.0.0
    if (json_get_required_string(obj, "dst", &s) < 0) {
        if (inet_pton(AF_INET, "0.0.0.0", &ina) != 1)
            return -EINVAL;
        out->dst_ip = rte_be_to_cpu_32(ina.s_addr);
    }
    else {
        if (inet_pton(AF_INET, s, &ina) != 1)
            return -EINVAL;
        out->dst_ip = rte_be_to_cpu_32(ina.s_addr);
    }

    //if no prefix, default to 0
    if (json_get_required_int(obj, "src_prefix", &v) < 0){
        out->src_prefix = 0;
    }
    else {
        out->src_prefix = (uint8_t)v;
    }

    if (json_get_required_int(obj, "dst_prefix", &v) < 0){
        out->dst_prefix = 0;
    }
    else {
        out->dst_prefix = (uint8_t)v;
    }

    /* ports & proto (host-order integers) */
    if( json_get_required_string(obj, "src_ports", &s) < 0){
        out->src_port_lo = 0;
        out->src_port_hi = 65535;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->src_port_lo = 0;
            out->src_port_hi = 65535;
        }
        else{
            out->src_port_lo = lo;
            out->src_port_hi = hi;
        }
    }   

    if ( json_get_required_string(obj, "dst_ports", &s) < 0){
        out->dst_port_lo = 0;
        out->dst_port_hi = 65535;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->dst_port_lo = 0;
            out->dst_port_hi = 65535;
        }
        else{
            out->dst_port_lo = lo;
            out->dst_port_hi = hi;
        }
    }

    //wildcard proto is 0 
    if (json_get_required_int(obj, "proto", &v) < 0){
        out->proto = 0; /* any */
    }
    else {
        out->proto = (uint8_t)v;
    }

    /* ingress port range */
    if(json_get_required_string(obj, "in_ports", &s) == 0){
        if (parse_input_port_list(s, global_port_list, &out->in_port_lo, &out->in_port_hi) < 0){
            return -EINVAL;
        }
    }
    else {
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }

    //default to 0
    if (json_get_required_int(obj, "priority", &v) < 0 || v < 1){
        out->priority = 1;
    }
    else { 
        out->priority = (int32_t)v;
    }

    /* action */
    json_t *act = json_object_get(obj, "action");
    if (!act || !json_is_object(act))
        return -EINVAL;
    if (ppr_acl_action_from_json(act, global_port_list, &out->action) < 0)
        return -EINVAL;

    return 0;
}

/* ---------- IPv6 rule <-> JSON ---------- */

static json_t *ppr_acl_ip6_rule_to_json(ppr_acl_runtime_t *acl_rt, ppr_ports_t *global_port_list,
                                        const ppr_acl_ip6_rule_cfg_t *cfg ,unsigned int rule_index)
{
    if (!acl_rt || !cfg || !global_port_list )
        return NULL;

    json_t *obj = json_object();
    if (!obj)
        return NULL;

    //get acl rule stats
    ppr_acl_rule_db_stats_t *acl_stats = atomic_load_explicit(&acl_rt->global_stats_curr, memory_order_acquire); 
    if (acl_stats){
        ppr_acl_rule_stats_t rule_stats = acl_stats->ip6[rule_index];
        uint64_t total_flows = atomic_load_explicit(&rule_stats.total_flows, memory_order_relaxed);
        uint64_t active_flows = atomic_load_explicit(&rule_stats.active_flows, memory_order_relaxed);

        json_object_set_new(obj, "total_flows", json_integer(total_flows));
        json_object_set_new(obj, "active_flows", json_integer(active_flows));
    }
    else {
        json_object_set_new(obj, "total_flows", json_integer(0));
        json_object_set_new(obj, "active_flows", json_integer(0));
    }

    char tenant_id_buf[64];
    snprintf(tenant_id_buf, sizeof(tenant_id_buf), "%u:%u", cfg->tenant_id_lo, cfg->tenant_id_hi);
    json_object_set_new(obj, "tenant_ids", json_string(tenant_id_buf));

    json_object_set_new(obj, "src_prefix", json_integer(cfg->src_prefix));
    json_object_set_new(obj, "dst_prefix", json_integer(cfg->dst_prefix));

    char buf[INET6_ADDRSTRLEN];
    struct in6_addr in6;

    memcpy(&in6.s6_addr[0],  cfg->src_ip, 16);
    if (!inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "src", json_string(buf));

    memcpy(&in6.s6_addr[0], cfg->dst_ip, 16);
    if (!inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "dst", json_string(buf));

    /* ports / proto */
    char src_port_buf[64];
    char dst_port_buf[64];
    snprintf(src_port_buf, sizeof(src_port_buf), "%u:%u", cfg->src_port_lo, cfg->src_port_hi);
    snprintf(dst_port_buf, sizeof(dst_port_buf), "%u:%u", cfg->dst_port_lo, cfg->dst_port_hi);
    json_object_set_new(obj, "src_ports", json_string(src_port_buf));
    json_object_set_new(obj, "dst_ports", json_string(dst_port_buf));
    json_object_set_new(obj, "proto",        json_integer(cfg->proto));

    /* ingress port range */
    ppr_port_entry_t *port_entry_lo = ppr_find_port_byid(global_port_list, cfg->in_port_lo);
    ppr_port_entry_t *port_entry_hi = ppr_find_port_byid(global_port_list, cfg->in_port_hi);
    if( port_entry_lo != NULL && port_entry_hi != NULL){
        char in_port_buf[128];
        snprintf(in_port_buf, sizeof(in_port_buf), "%s-%s", port_entry_lo->name, port_entry_hi->name);
        json_object_set_new(obj, "in_ports", json_string(in_port_buf));
    }
    else {
        json_object_set_new(obj, "in_ports", json_string("any"));
    }   

    json_object_set_new(obj, "priority", json_integer(cfg->priority));
    json_object_set_new(obj, "rule_id",  json_integer(cfg->rule_id));

    json_t *act = ppr_policy_action_to_json(global_port_list, &cfg->action);
    if (!act) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "action", act);

    return obj;
}

static int ppr_acl_ip6_rule_from_json(const json_t *obj, ppr_ports_t *global_port_list, ppr_acl_ip6_rule_cfg_t *out)
{
    if (!obj || !json_is_object(obj) || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));

    int64_t v;
    const char *s;

    /* tenant ID */
    if(json_get_required_string(obj, "tenant_ids", &s) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else {
        uint32_t ten_lo, ten_hi;
        if(parse_tenant_range(s, &ten_lo, &ten_hi) < 0){
            out->tenant_id_lo = 0;
            out->tenant_id_hi = 0xFFFFFFFF;
        }
        else{
            out->tenant_id_lo = ten_lo;
            out->tenant_id_hi = ten_hi;
        }
    }

    /* src/dst addresses */
    //default to :: if not present
    struct in6_addr in6;
    if (json_get_required_string(obj, "src", &s) < 0){
        memset(out->src_ip, 0, 16);  //default to ::
    }
    else {
        if (inet_pton(AF_INET6, s, &in6) != 1)
            return -EINVAL;
        memcpy(out->src_ip, in6.s6_addr, 16);
    }


    if (json_get_required_string(obj, "dst", &s) < 0){
        memset(out->dst_ip, 0, 16);  //default to ::
    }
    else {
        if (inet_pton(AF_INET6, s, &in6) != 1)
            return -EINVAL;
        memcpy(out->dst_ip, in6.s6_addr, 16);
    }

    /* src/dst ip6 prefixes */
    //default to 0 if not present
    if (json_get_required_int(obj, "src_prefix", &v) < 0){
        out->src_prefix = 0;
    }
    else {
        out->src_prefix = (uint8_t)v;
    }

    if (json_get_required_int(obj, "dst_prefix", &v) < 0){
        out->dst_prefix = 0;
    }
    else { 
        out->dst_prefix = (uint8_t)v;
    }

    /* ports & proto */
    if( json_get_required_string(obj, "src_ports", &s) < 0){
        out->src_port_lo = 0;
        out->src_port_hi = 65535;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->src_port_lo = 0;
            out->src_port_hi = 65535;
        }
        else{
            out->src_port_lo = lo;
            out->src_port_hi = hi;
        }
    }

    if ( json_get_required_string(obj, "dst_ports", &s) < 0){
        out->dst_port_lo = 0;
        out->dst_port_hi = 65535;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->dst_port_lo = 0;
            out->dst_port_hi = 65535;
        }
        else{
            out->dst_port_lo = lo;
            out->dst_port_hi = hi;
        }
    }

    //default 0
    if (json_get_required_int(obj, "proto", &v) < 0){
        out->proto = 0; /* any */
    }
    else {
        out->proto = (uint8_t)v;
    }

    /* ingress ports */
    /* ingress port range */
    if(json_get_required_string(obj, "in_ports", &s) == 0){
        if (parse_input_port_list(s, global_port_list, &out->in_port_lo, &out->in_port_hi) < 0){
            return -EINVAL;
        }
    }
    else {
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }

    //priority field default to 0
    if (json_get_required_int(obj, "priority", &v) < 0 || v < 1){
        out->priority = 1;
    }
    else {
        out->priority = (int32_t)v;
    }

    json_t *act = json_object_get(obj, "action");
    if (!act || !json_is_object(act))
        return -EINVAL;
    if (ppr_acl_action_from_json(act, global_port_list, &out->action) < 0)
        return -EINVAL;

    return 0;
}

/* ---------- L2 rule <-> JSON ---------- */

static json_t *ppr_acl_l2_rule_to_json(ppr_acl_runtime_t *acl_rt, ppr_ports_t *global_port_list, 
                                       const ppr_acl_l2_rule_cfg_t *cfg, unsigned int rule_index)
{
    if (!acl_rt || !cfg || !global_port_list )
        return NULL;

    json_t *obj = json_object();
    if (!obj)
        return NULL;

    //get acl rule stats
    //get acl rule stats
    ppr_acl_rule_db_stats_t *acl_stats = atomic_load_explicit(&acl_rt->global_stats_curr, memory_order_acquire); 
    if (acl_stats){
        ppr_acl_rule_stats_t rule_stats = acl_stats->l2[rule_index];
        uint64_t total_flows = atomic_load_explicit(&rule_stats.total_flows, memory_order_relaxed);
        uint64_t active_flows = atomic_load_explicit(&rule_stats.active_flows, memory_order_relaxed);

        json_object_set_new(obj, "total_flows", json_integer(total_flows));
        json_object_set_new(obj, "active_flows", json_integer(active_flows));
    }
    else {
        json_object_set_new(obj, "total_flows", json_integer(0));
        json_object_set_new(obj, "active_flows", json_integer(0));
    }

    char tenant_id_buf[64];
    snprintf(tenant_id_buf, sizeof(tenant_id_buf), "%u:%u", cfg->tenant_id_lo, cfg->tenant_id_hi);
    json_object_set_new(obj, "tenant_ids", json_string(tenant_id_buf));

    /* ingress port range */
    ppr_port_entry_t *port_entry_lo = ppr_find_port_byid(global_port_list, cfg->in_port_lo);
    ppr_port_entry_t *port_entry_hi = ppr_find_port_byid(global_port_list, cfg->in_port_hi);
    if( port_entry_lo != NULL && port_entry_hi != NULL){
        char in_port_buf[128];
        snprintf(in_port_buf, sizeof(in_port_buf), "%s-%s", port_entry_lo->name, port_entry_hi->name);
        json_object_set_new(obj, "in_ports", json_string(in_port_buf));
    }
    else {
        json_object_set_new(obj, "in_ports", json_string("any"));
    }


    char outer_vlan_buf[128];
    char inner_vlan_buf[128];
    snprintf(outer_vlan_buf, sizeof(outer_vlan_buf), "%u:%u", cfg->outer_vlan_lo, cfg->outer_vlan_hi);
    snprintf(inner_vlan_buf, sizeof(inner_vlan_buf), "%u:%u", cfg->inner_vlan_lo, cfg->inner_vlan_hi);
    json_object_set_new(obj, "outer_vlans", json_string(outer_vlan_buf));
    json_object_set_new(obj, "inner_vlans", json_string(inner_vlan_buf));
    json_object_set_new(obj, "ether_type",    json_integer(cfg->ether_type));
    json_object_set_new(obj, "is_mac_match",  json_boolean(cfg->is_mac_match != 0));
    json_object_set_new(obj, "priority",      json_integer(cfg->priority));
    json_object_set_new(obj, "rule_id",       json_integer(cfg->rule_id));

    char macbuf[32];

    format_mac(&cfg->src_mac, macbuf, sizeof(macbuf));
    json_object_set_new(obj, "src_mac", json_string(macbuf));

    format_mac(&cfg->dst_mac, macbuf, sizeof(macbuf));
    json_object_set_new(obj, "dst_mac", json_string(macbuf));

    json_t *act = ppr_policy_action_to_json(global_port_list, &cfg->action);
    if (!act) {
        json_decref(obj);
        return NULL;
    }
    json_object_set_new(obj, "action", act);

    return obj;
}

static int ppr_acl_l2_rule_from_json(const json_t *obj, ppr_ports_t *global_port_list, ppr_acl_l2_rule_cfg_t *out)
{
    if (!obj || !json_is_object(obj) || !out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));

    int64_t v;
    const char *s;

    //default to 0
    if(json_get_required_string(obj, "tenant_ids", &s) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else {
        uint32_t ten_lo, ten_hi;
        if(parse_tenant_range(s, &ten_lo, &ten_hi) < 0){
            out->tenant_id_lo = 0;
            out->tenant_id_hi = 0xFFFFFFFF;
        }
        else{
            out->tenant_id_lo = ten_lo;
            out->tenant_id_hi = ten_hi;
        }
    }

    /* ingress port range */
    if(json_get_required_string(obj, "in_ports", &s) == 0){
        if (parse_input_port_list(s, global_port_list, &out->in_port_lo, &out->in_port_hi) < 0){
            return -EINVAL;
        }
    }
    else {
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }

    //default to 0 
    if (json_get_required_string(obj, "outer_vlans", &s) < 0){
        out->outer_vlan_lo = 0;
        out->outer_vlan_hi = 4095;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->outer_vlan_lo = 0;
            out->outer_vlan_hi = 4095;
        }
        else{
            out->outer_vlan_lo = lo;
            out->outer_vlan_hi = hi;
        }
    }  

    if ( json_get_required_string(obj, "inner_vlans", &s) < 0){
        out->inner_vlan_lo = 0;
        out->inner_vlan_hi = 4095;
    }
    else {
        uint16_t lo, hi;
        if (parse_port_range(s, &lo, &hi) < 0){
            out->inner_vlan_lo = 0;
            out->inner_vlan_hi = 4095;
        }
        else{
            out->inner_vlan_lo = lo;
            out->inner_vlan_hi = hi;
        }
    }

    //default to 0 wildcard
    if (json_get_required_int(obj, "ether_type", &v) < 0){
        out->ether_type = 0;
    }
    else { 
        out->ether_type = (uint16_t)v;
    }

    /* is_mac_match is boolean */
    json_t *jm = json_object_get(obj, "is_mac_match");
    
    if (!jm || !json_is_boolean(jm)){
        out->is_mac_match = 0; /* default to 0 */   
    }
    else { 
        out->is_mac_match = json_boolean_value(jm) ? 1 : 0;
    }

    //default to 0
    if (json_get_required_int(obj, "priority", &v) < 0 || v < 1){
        out->priority = 1;
    }
    else { 
        out->priority = (int32_t)v;
    }


    /* MAC addresses */
    if (json_get_required_string(obj, "src_mac", &s) < 0){
        if (parse_mac("0:0:0:0:0:0", &out->src_mac) < 0)
            return -EINVAL;        
    }
    else { 
        if (parse_mac(s, &out->src_mac) < 0)
            return -EINVAL;
    }

    if (json_get_required_string(obj, "dst_mac", &s) < 0){
        if (parse_mac("0:0:0:0:0:0", &out->dst_mac) < 0)
            return -EINVAL;        
    }
    else { 
        if (parse_mac(s, &out->dst_mac) < 0)
            return -EINVAL;
    }

    json_t *act = json_object_get(obj, "action");
    if (!act || !json_is_object(act))
        return -EINVAL;
    if (ppr_acl_action_from_json(act, global_port_list, &out->action) < 0)
        return -EINVAL;

    return 0;
}

/* ---------------------------- RPC API for ACL Rules ---------------------------------- */

/** 
* Return a JSON list of all ACL rules in the database.
* @param reply_root
*   Pointer to JSON object to populate with reply data.
* @param args
*   Pointer to JSON object containing command arguments (not used).
* @param thread_args
*   Pointer to thread arguments structure.
* @return
*   0 on success, negative errno on failure.
**/
int ppr_cmd_get_acl_db(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    (void) args;

    //get ACL DB and runtime pointers
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_acl_runtime_t *acl_rt = thread_args->acl_runtime;

    ppr_ports_t *global_port_list = thread_args->global_port_list;

    //guard on null 
    if(!acl_db || !acl_rt){
        return -EINVAL;
    }
    
    //iterate over all IPv4 rules and add to JSON array
    json_t *ipv4_rules = json_array();
    if(!ipv4_rules){
        return -ENOMEM;
    }

    for (unsigned int i=0; i < PPR_ACL_MAX_RULES; i++){
        ppr_acl_ip4_rule_cfg_t *rule_cfg = &acl_db->ip4.rules[i];
        
        //if rule slot not in use, skip
        if(!rule_cfg || !acl_db->ip4.used[i]){
            continue;
        }

        json_t *rule_json = ppr_acl_ip4_rule_to_json(acl_rt, global_port_list, rule_cfg,i);
        if(!rule_json){
            json_decref(ipv4_rules);
            return -ENOMEM;
        }
        json_array_append_new(ipv4_rules, rule_json);
    }
    json_object_set_new(reply_root, "ipv4_rules", ipv4_rules);

    //iterate over all IPv6 rules and add to JSON array
    json_t *ipv6_rules = json_array();
    if(!ipv6_rules){
        return -ENOMEM;
    }
    for (unsigned int i=0; i < PPR_ACL_MAX_RULES; i++){
        ppr_acl_ip6_rule_cfg_t *rule_cfg = &acl_db->ip6.rules[i];
        
        //if rule slot not in use, skip
        if(!rule_cfg || !acl_db->ip6.used[i]){
            continue;
        }

        json_t *rule_json = ppr_acl_ip6_rule_to_json(acl_rt, global_port_list, rule_cfg,i);
        if(!rule_json){
            json_decref(ipv6_rules);
            return -ENOMEM;
        }
        json_array_append_new(ipv6_rules, rule_json);
    }
    json_object_set_new(reply_root, "ipv6_rules", ipv6_rules);

    //iterate over all L2 rules and add to JSON array
    json_t *l2_rules = json_array();
    if(!l2_rules){
        return -ENOMEM;
    }   
    for (unsigned int i=0; i < PPR_ACL_MAX_RULES; i++){
        ppr_acl_l2_rule_cfg_t *rule_cfg = &acl_db->l2.rules[i];
        
        //if rule slot not in use, skip
        if(!rule_cfg || !acl_db->l2.used[i]){
            continue;
        }

        json_t *rule_json = ppr_acl_l2_rule_to_json(acl_rt, global_port_list, rule_cfg ,i );
        if(!rule_json){
            json_decref(l2_rules);
            return -ENOMEM;
        }
        json_array_append_new(l2_rules, rule_json);
    }
    json_object_set_new(reply_root, "l2_rules", l2_rules);

    return 0;
}

/** 
* Add a new ACL rule to the database. Takes a json object with the rule_type and rule_cfg properties. 
* @param reply_root
*   Pointer to JSON object to populate with reply data.
* @param args
*   Pointer to JSON object containing command arguments.
* @param thread_args
*   Pointer to thread arguments structure.
* @return
*   0 on success, negative errno on failure.
**/
int ppr_cmd_add_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    //get ACL DB and runtime pointers
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_acl_runtime_t *acl_rt = thread_args->acl_runtime;
    ppr_ports_t *global_port_list = thread_args->global_port_list;

    //guard on null 
    if(!acl_db || !acl_rt || !args){
        return -EINVAL;
    }

    //debug print args struct 
    char *args_str = json_dumps(args, JSON_INDENT(2));
    if(args_str){
        printf("Add ACL Rule Args:\n%s\n", args_str);
        free(args_str);
    }

    //determine rule type
    const char *rule_type = NULL;
    if(json_get_required_string(args, "rule_type", &rule_type) < 0){
        return -EINVAL;
    }

    //get the rule config object 
    const json_t *rule_cfg_json = json_object_get(args, "rule_cfg");
    if(!rule_cfg_json || !json_is_object(rule_cfg_json)){
        return -EINVAL;
    }

    int ret = 0;
    uint32_t assigned_rule_id = 0;

    if(strcmp(rule_type, "ipv4") == 0){
        //parse IPv4 rule from JSON
        ppr_acl_ip4_rule_cfg_t rule_cfg;
        if(ppr_acl_ip4_rule_from_json(rule_cfg_json, global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //add rule to ACL DB
        ret = ppr_acl_db_add_ip4_rule(acl_db, &rule_cfg, &assigned_rule_id);
        if(ret < 0){
            return ret;
        }

    } else if(strcmp(rule_type, "ipv6") == 0){
        //parse IPv6 rule from JSON
        ppr_acl_ip6_rule_cfg_t rule_cfg;
        if(ppr_acl_ip6_rule_from_json(rule_cfg_json,global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //add rule to ACL DB
        ret = ppr_acl_db_add_ip6_rule(acl_db, &rule_cfg, &assigned_rule_id);
        if(ret < 0){
            return ret;
        }

    } else if(strcmp(rule_type, "l2") == 0){
        //parse L2 rule from JSON
        ppr_acl_l2_rule_cfg_t rule_cfg;
        if(ppr_acl_l2_rule_from_json(rule_cfg_json,global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //add rule to ACL DB
        ret = ppr_acl_db_add_l2_rule(acl_db, &rule_cfg, &assigned_rule_id);
        if(ret < 0){
            return ret;
        }

    } else {
        return -EINVAL; //unknown rule type
    }

    //return assigned rule ID in reply
    json_object_set_new(reply_root, "assigned_rule_id", json_integer(assigned_rule_id));
    return 0;
}

/** 
* Update an existing ACL rule in the database. Takes a json object with the rule_type, rule_id and rule_cfg properties. 
* @param reply_root
*   Pointer to JSON object to populate with reply data.
* @param args
*   Pointer to JSON object containing command arguments.
* @param thread_args
*   Pointer to thread arguments structure.
* @return
*   0 on success, negative errno on failure.    
**/
int ppr_cmd_update_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    (void) reply_root;
    
    //get ACL DB and runtime pointers
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_acl_runtime_t *acl_rt = thread_args->acl_runtime;
    ppr_ports_t *global_port_list = thread_args->global_port_list;

    //guard on null 
    if(!acl_db || !acl_rt || !args){
        return -EINVAL;
    }

    //determine rule type
    const char *rule_type = NULL;
    if(json_get_required_string(args, "rule_type", &rule_type) < 0){
        return -EINVAL;
    }

    //make sure we have a rule id 
    int rule_id = -1; 
    if (json_get_required_int(args, "rule_id", (int64_t *)&rule_id) < 0){
        return -EINVAL;
    }

    //get the rule config object 
    const json_t *rule_cfg_json = json_object_get(args, "rule_cfg");
    if(!rule_cfg_json || !json_is_object(rule_cfg_json)){
        return -EINVAL;
    }    

    if (strcmp(rule_type, "ipv4") == 0){
        //parse IPv4 rule from JSON
        ppr_acl_ip4_rule_cfg_t rule_cfg;
        if(ppr_acl_ip4_rule_from_json(rule_cfg_json, global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //update rule in ACL DB
        return ppr_acl_db_update_ip4_rule(acl_db, rule_id, &rule_cfg);

    } else if(strcmp(rule_type, "ipv6") == 0){
        //parse IPv6 rule from JSON
        ppr_acl_ip6_rule_cfg_t rule_cfg;
        if(ppr_acl_ip6_rule_from_json(rule_cfg_json, global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //update rule in ACL DB
        return ppr_acl_db_update_ip6_rule(acl_db, rule_id, &rule_cfg);

    } else if(strcmp(rule_type, "l2") == 0){
        //parse L2 rule from JSON
        ppr_acl_l2_rule_cfg_t rule_cfg;
        if(ppr_acl_l2_rule_from_json(rule_cfg_json, global_port_list, &rule_cfg) < 0){
            return -EINVAL;
        }

        //update rule in ACL DB
        return ppr_acl_db_update_l2_rule(acl_db, rule_id, &rule_cfg);

    } else {
        return -EINVAL; //unknown rule type
    }
}

int ppr_cmd_delete_acl_rule(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    
    (void) reply_root;

    //get ACL DB and runtime pointers
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_acl_runtime_t *acl_rt = thread_args->acl_runtime;
    
    
    //guard on null 
    if(!acl_db || !acl_rt || !args){
        return -EINVAL;
    }

    //determine rule type
    const char *rule_type = NULL;
    if(json_get_required_string(args, "rule_type", &rule_type) < 0){
        return -EINVAL;
    }

    //make sure we have a rule id 
    int rule_id = -1; 
    if (json_get_required_int(args, "rule_id", (int64_t *)&rule_id) < 0){
        return -EINVAL;
    }

    if (strcmp(rule_type, "ipv4") == 0){
        //delete rule from ACL DB
        return ppr_acl_db_del_ip4_rule(acl_db, rule_id);

    } else if(strcmp(rule_type, "ipv6") == 0){
        //delete rule from ACL DB
        return ppr_acl_db_del_ip6_rule(acl_db, rule_id);

    } else if(strcmp(rule_type, "l2") == 0){
        //delete rule from ACL DB
        return ppr_acl_db_del_l2_rule(acl_db, rule_id);

    } else {
        return -EINVAL; //unknown rule type
    }
}

/**
* Check and return the status of the ACL database.
* @param reply_root
*   Pointer to JSON object to populate with reply data.
* @param args
*   Pointer to JSON object containing command arguments (not used).
* @param thread_args
*   Pointer to thread arguments structure.
* @return
*   0 on success, negative errno on failure.
**/
int ppr_cmd_check_acl_status(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    (void) args;

    //get ACL DB pointer
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;

    //guard on null 
    if(!acl_db){
        return -EINVAL;
    }

    //return number of rules in each category
    json_object_set_new(reply_root, "ipv4_rule_count", json_integer(acl_db->ip4.active_count));
    json_object_set_new(reply_root, "ipv6_rule_count", json_integer(acl_db->ip6.active_count));
    json_object_set_new(reply_root, "l2_rule_count",   json_integer(acl_db->l2.active_count));

    //return dirty flags 
    json_object_set_new(reply_root, "db_dirty",   json_boolean(acl_db->dirty ? 1 : 0));
    json_object_set_new(reply_root, "ipv4_dirty", json_boolean(acl_db->ip4.dirty ? 1 : 0));
    json_object_set_new(reply_root, "ipv6_dirty", json_boolean(acl_db->ip6.dirty ? 1 : 0));
    json_object_set_new(reply_root, "l2_dirty",   json_boolean(acl_db->l2.dirty ? 1 : 0));

    return 0;
}

/** 
* ACL contexts are built, then swapped. This command rebuilds the runtime contexts and performs a controlled pointer swap. 
* @param reply_root
*   Pointer to JSON object to populate with reply data.
* @param args   
**/
int ppr_cmd_acl_db_commit(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    (void) reply_root;
    (void) args;

    //get ACL DB and runtime pointers
    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_acl_runtime_t *acl_rt = thread_args->acl_runtime;

    //guard on null 
    if(!acl_db || !acl_rt){
        return -EINVAL;
    }

    //commit changes from CP to ACL runtime
    return ppr_acl_db_commit(acl_rt, acl_db);
}