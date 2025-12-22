// ppr_acl_yaml.c
#include "ppr_acl_yaml.h"

#include <string.h>
#include <arpa/inet.h>
#include "ppr_log.h"
#include "ppr_actions.h"      // ppr_policy_action_t etc.
#include "ppr_acl_db.h"

/* -------- libcyaml schema -------- */

/* Reusable schema for a heap-allocated string (char *). */
static const cyaml_schema_value_t ppr_yaml_string_ptr_value = {
    CYAML_VALUE_STRING(
        CYAML_FLAG_POINTER,   /* heap-allocated C string */
        char,                 /* NOTE: char, not char *  */
        0,
        CYAML_UNLIMITED)
};

/* Action mapping: ppr_yaml_acl_action_t */
static const cyaml_schema_field_t ppr_yaml_acl_action_fields[] = {
    CYAML_FIELD_STRING_PTR(
        "default_policy", CYAML_FLAG_POINTER,
        ppr_yaml_acl_action_t, default_policy,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_END
};

/* IPv4 rule mapping */
static const cyaml_schema_field_t ppr_yaml_acl_ip4_rule_fields[] = {
    CYAML_FIELD_STRING_PTR("tenant_ids", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, tenant_ids,
                     0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("src", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip4_rule_t, src,
                        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("src_prefix", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, src_prefix),

    CYAML_FIELD_STRING_PTR("dst", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip4_rule_t, dst,
                        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("dst_prefix", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, dst_prefix),

    CYAML_FIELD_STRING_PTR("src_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, src_ports,  0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("dst_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, dst_ports,  0, CYAML_UNLIMITED),


    CYAML_FIELD_STRING_PTR("proto", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip4_rule_t, proto,
                        0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("in_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip4_rule_t, in_ports, 0, CYAML_UNLIMITED),


    CYAML_FIELD_INT("priority", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                    ppr_yaml_acl_ip4_rule_t, priority),

    CYAML_FIELD_MAPPING("action", CYAML_FLAG_DEFAULT,
                        ppr_yaml_acl_ip4_rule_t, action,
                        ppr_yaml_acl_action_fields),

    CYAML_FIELD_END
};

/* IPv6 rule mapping */
static const cyaml_schema_field_t ppr_yaml_acl_ip6_rule_fields[] = {
    CYAML_FIELD_STRING_PTR("tenant_ids", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, tenant_ids,
                     0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("src", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip6_rule_t, src,
                        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("src_prefix", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, src_prefix),

    CYAML_FIELD_STRING_PTR("dst", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip6_rule_t, dst,
                        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("dst_prefix", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, dst_prefix),

    CYAML_FIELD_STRING_PTR("src_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, src_ports, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("dst_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, dst_ports, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("proto", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                        ppr_yaml_acl_ip6_rule_t, proto,
                        0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("in_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_ip6_rule_t, in_ports, 0, CYAML_UNLIMITED),


    CYAML_FIELD_INT("priority", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                    ppr_yaml_acl_ip6_rule_t, priority),

    CYAML_FIELD_MAPPING("action", CYAML_FLAG_DEFAULT,
                        ppr_yaml_acl_ip6_rule_t, action,
                        ppr_yaml_acl_action_fields),

    CYAML_FIELD_END
};

/* L2 rule mapping */
static const cyaml_schema_field_t ppr_yaml_acl_l2_rule_fields[] = {
    CYAML_FIELD_STRING_PTR("tenant_ids", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_l2_rule_t, tenant_ids, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("in_ports", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_l2_rule_t, in_ports, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("outer_vlans", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_l2_rule_t, outer_vlans, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("inner_vlans", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                     ppr_yaml_acl_l2_rule_t, inner_vlans, 0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("ether_type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                           ppr_yaml_acl_l2_rule_t, ether_type,
                           0, CYAML_UNLIMITED),
                           

    CYAML_FIELD_STRING_PTR("src_mac", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                           ppr_yaml_acl_l2_rule_t, src_mac,
                           0, CYAML_UNLIMITED),

    CYAML_FIELD_STRING_PTR("dst_mac", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                           ppr_yaml_acl_l2_rule_t, dst_mac,
                           0, CYAML_UNLIMITED),

    CYAML_FIELD_INT("priority", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL,
                    ppr_yaml_acl_l2_rule_t, priority),

    CYAML_FIELD_MAPPING("action", CYAML_FLAG_DEFAULT,
                        ppr_yaml_acl_l2_rule_t, action,
                        ppr_yaml_acl_action_fields),

    CYAML_FIELD_END
};

/* IPv4 rule schema: sequence element type */
static const cyaml_schema_value_t ppr_yaml_acl_ip4_rule_schema = {
    CYAML_VALUE_MAPPING(
        CYAML_FLAG_DEFAULT,           // <-- FIXED
        ppr_yaml_acl_ip4_rule_t,
        ppr_yaml_acl_ip4_rule_fields),
};

/* IPv6 rule schema: sequence element type */
static const cyaml_schema_value_t ppr_yaml_acl_ip6_rule_schema = {
    CYAML_VALUE_MAPPING(
        CYAML_FLAG_DEFAULT,           // <-- FIXED
        ppr_yaml_acl_ip6_rule_t,
        ppr_yaml_acl_ip6_rule_fields),
};

/* L2 rule schema: sequence element type */
static const cyaml_schema_value_t ppr_yaml_acl_l2_rule_schema = {
    CYAML_VALUE_MAPPING(
        CYAML_FLAG_DEFAULT,           // <-- FIXED
        ppr_yaml_acl_l2_rule_t,
        ppr_yaml_acl_l2_rule_fields),
};

/* rules: container of sequences */
static const cyaml_schema_field_t ppr_yaml_acl_rules_fields[] = {
    CYAML_FIELD_SEQUENCE(
        "ip4", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
        ppr_yaml_acl_rules_t, ip4,
        &ppr_yaml_acl_ip4_rule_schema,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_SEQUENCE(
        "ip6", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
        ppr_yaml_acl_rules_t, ip6,
        &ppr_yaml_acl_ip6_rule_schema,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_SEQUENCE(
        "l2", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
        ppr_yaml_acl_rules_t, l2,
        &ppr_yaml_acl_l2_rule_schema,
        0, CYAML_UNLIMITED),

    CYAML_FIELD_END
};

/* root: has a single "acl_rules" mapping */
static const cyaml_schema_field_t ppr_yaml_acl_root_fields[] = {
    CYAML_FIELD_MAPPING(
        "acl_rules", CYAML_FLAG_DEFAULT,
        ppr_yaml_acl_root_t, rules,
        ppr_yaml_acl_rules_fields),

    CYAML_FIELD_END
};

/* top-level schema: pointer, because we pass ppr_yaml_acl_root_t ** to cyaml_load_file */
static const cyaml_schema_value_t ppr_yaml_acl_root_schema = {
    CYAML_VALUE_MAPPING(
        CYAML_FLAG_POINTER,
        ppr_yaml_acl_root_t,
        ppr_yaml_acl_root_fields),
};

/* --- small helpers reused from your JSON code --- */

static uint8_t proto_from_str(const char *s)
{
    if (!s) return 0;

    if (!strcasecmp(s, "any"))  return 0;
    if (!strcasecmp(s, "tcp"))  return IPPROTO_TCP;
    if (!strcasecmp(s, "udp"))  return IPPROTO_UDP;
    if (!strcasecmp(s, "icmp")) return IPPROTO_ICMP;
    // extend as needed
    return 0;
}

static uint16_t ethertype_from_str(const char *s)
{
    if (!s) return 0;
    if (!strcasecmp(s, "any"))  return 0;
    if (!strcasecmp(s, "ipv4")) return 0x0800;
    if (!strcasecmp(s, "ipv6")) return 0x86DD;
    if (!strcasecmp(s, "arp"))  return 0x0806;
    return 0;
}

static int parse_mac(const char *s, struct rte_ether_addr *mac)
{
    unsigned int b[6];
    if (!s) return -EINVAL;

    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -EINVAL;

    for (int i = 0; i < 6; i++)
        mac->addr_bytes[i] = (uint8_t)b[i];

    return 0;
}

//<TODO> this duplicates logic in the main yaml parser, combine?
static ppr_flow_action_kind_t policy_from_str(const char *s)
{
    if (!s) return FLOW_ACT_DROP;

    if (!strcasecmp(s, "FLOW_ACT_NOOP"))         return FLOW_ACT_NOOP;
    if (!strcasecmp(s, "FLOW_ACT_DROP"))         return FLOW_ACT_DROP;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_SRCMAC")) return FLOW_ACT_MODIFY_SRCMAC;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_SRCIP"))  return FLOW_ACT_MODIFY_SRCIP;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_SRCPORT"))return FLOW_ACT_MODIFY_SRCPORT;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_SRC_ALL")) return FLOW_ACT_MODIFY_SRC_ALL;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_DSTMAC")) return FLOW_ACT_MODIFY_DSTMAC;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_DSTIP"))  return FLOW_ACT_MODIFY_DSTIP;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_DSTPORT"))return FLOW_ACT_MODIFY_DSTPORT;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_DST_ALL")) return FLOW_ACT_MODIFY_DST_ALL;
    if (!strcasecmp(s, "FLOW_ACT_MODIFY_ALL"))    return FLOW_ACT_MODIFY_ALL;   
    // extend as you add types
    return FLOW_ACT_DROP;
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


/** 
* Convert a YAML action structure into internal representation.
* @param ya Input YAML action structure
* @param ports Ports database
* @param out Output internal action structure
* @return 0 on success, negative errno on failure
**/
static int yaml_action_to_policy(const ppr_yaml_acl_action_t *ya,
                                 ppr_ports_t *global_port_list,
                                 ppr_policy_action_t *out)
{
    memset(out, 0, sizeof(*out));

    //set default policy action from string in yaml, defaults to drop policy if not present or invalid
    out->default_policy = policy_from_str(ya->default_policy);

    out->hit = false;
    return 0;
}


/* --------------------------------- Per Ruletype YAML Struct -> Internal Struct Conversions W/ Wildcard Handling ---------------------*/

/** 
* Convert a Libcyaml IPv4 rule structure into internal representation. Check for omitted fields and set defaults for wildcards. 
* @param y Input YAML IPv4 rule structure
* @param ports Ports database
* @param out Output internal IPv4 rule configuration structure
* @return 0 on success, negative errno on failure
**/
static int yaml_ip4_to_cfg(const ppr_yaml_acl_ip4_rule_t *y,
                           ppr_ports_t *global_port_list,
                           ppr_acl_ip4_rule_cfg_t *out)
{
    memset(out, 0, sizeof(*out));
    
    //set tenant id, default to 0 for all tenants
    uint32_t ten_lo, ten_hi;
    if(parse_tenant_range(y->tenant_ids, &ten_lo, &ten_hi) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else{
        out->tenant_id_lo = ten_lo;
        out->tenant_id_hi = ten_hi;
    }

    struct in_addr ina;
    //if no ip address provided use 0.0.0.0
    if (!y->src ){
        inet_pton(AF_INET, "0.0.0.0", &ina);
    }
    else { 
        if(inet_pton(AF_INET, y->src, &ina) != 1)
            return -EINVAL;
    }
    out->src_ip     = rte_be_to_cpu_32(ina.s_addr); //host order for rule creation 
    out->src_prefix = y->src_prefix;

    //if no ip address provided use 0.0.0.0
    if (!y->dst ){
        inet_pton(AF_INET, "0.0.0.0", &ina);
    }
    else { 
        if (inet_pton(AF_INET, y->dst, &ina) != 1)
            return -EINVAL; 
    }
    out->dst_ip     = rte_be_to_cpu_32(ina.s_addr); //host order for rule creation 
    out->dst_prefix = y->dst_prefix;

    //parse port ranges from strings
    uint16_t lo, hi;
    if (parse_port_range(y->src_ports, &lo, &hi) < 0){
        out->src_port_lo = 0;
        out->src_port_hi = 65535;
    }
    else{
        out->src_port_lo = lo;
        out->src_port_hi = hi;
    }

    //set dst ports, default to full range if not present
    if (parse_port_range(y->dst_ports, &lo, &hi) < 0){
        out->dst_port_lo = 0;
        out->dst_port_hi = 65535;
    }
    else { 
        out->dst_port_lo = lo;
        out->dst_port_hi = hi;
    }


    //set ingress ports, default to full range if not present
    if (parse_input_port_list(y->in_ports,global_port_list, &lo, &hi) < 0){
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }
    else { 
        out->in_port_lo = lo;
        out->in_port_hi = hi;
    }

    //set protocol, already includes wildcard handling from text conversion
    out->proto    = proto_from_str(y->proto);
    
    //set priority
    if(y->priority < 1){
        out->priority = 1;
    }
    else{
        out->priority = y->priority;
    }
    //populate action
    return yaml_action_to_policy(&y->action, global_port_list, &out->action);
}

/** 
* Convert a Libcyaml IPv6 rule structure into internal representation. Check for omitted fields and set defaults for wildcards. 
* @param y Input YAML IPv6 rule structure
* @param ports Ports database
* @param out Output internal IPv6 rule configuration structure
* @return 0 on success, negative errno on failure
**/
static int yaml_ip6_to_cfg(const ppr_yaml_acl_ip6_rule_t *y,
                           ppr_ports_t *global_port_list,
                           ppr_acl_ip6_rule_cfg_t *out)
{
    memset(out, 0, sizeof(*out));

    uint32_t ten_lo, ten_hi;
    if(parse_tenant_range(y->tenant_ids, &ten_lo, &ten_hi) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else{
        out->tenant_id_lo = ten_lo;
        out->tenant_id_hi = ten_hi;
    }

    //if no ip address provided use ::
    struct in6_addr in6;
    if (!y->src){
        inet_pton(AF_INET6, "::", &in6);
    }
    else { 
        if (inet_pton(AF_INET6,  y->src, &in6) != 1)
            return -EINVAL;
    }
    memcpy(out->src_ip, in6.s6_addr, 16);

    //if no ip address provided use ::
    if (!y->dst){
        inet_pton(AF_INET6, "::", &in6);
    }
    else { 
        if (inet_pton(AF_INET6,  y->dst, &in6) != 1)
            return -EINVAL;
    }

    memcpy(out->dst_ip, in6.s6_addr, 16);

    //copy prefixes, if not present will be zero
    out->src_prefix = y->src_prefix;
    out->dst_prefix = y->dst_prefix;

    /* Parse port ranges from strings */
    uint16_t lo, hi;
    //set src ports, default to full range if not present
    if (parse_port_range(y->src_ports, &lo, &hi) < 0){
        out->src_port_lo = 0;
        out->src_port_hi = 65535;
    }
    else {
        out->src_port_lo = lo;
        out->src_port_hi = hi;
    }

    //set dst ports, default to full range if not present
    if (parse_port_range(y->dst_ports, &lo, &hi) < 0){
        out->dst_port_lo = 0;
        out->dst_port_hi = 65535;
    }
    else {
        out->dst_port_lo = lo;
        out->dst_port_hi = hi;
    }

    //set ingress ports, default to full range if not present
    if (parse_input_port_list(y->in_ports,global_port_list, &lo, &hi) < 0){
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }
    else { 
        out->in_port_lo = lo;
        out->in_port_hi = hi;
    }

    //set protocol, already includes wildcard handling from text conversion
    out->proto      = proto_from_str(y->proto);

    if(y->priority < 1){
        out->priority = 1;
    }
    else{
        out->priority = y->priority;
    }

    //populate action
    return yaml_action_to_policy(&y->action, global_port_list, &out->action);
}

/** 
* Convert a Libcyaml L2 rule structure into internal representation. Check for omitted fields and set defaults for wildcards. 
* @param y Input YAML L2 rule structure
* @param ports Ports database
* @param out Output internal L2 rule configuration structure
* @return 0 on success, negative errno on failure   
**/
static int yaml_l2_to_cfg(const ppr_yaml_acl_l2_rule_t *y,
                          ppr_ports_t *global_port_list,
                          ppr_acl_l2_rule_cfg_t *out)
{

    memset(out, 0, sizeof(*out));

    uint32_t ten_lo, ten_hi;
    if(parse_tenant_range(y->tenant_ids, &ten_lo, &ten_hi) < 0){
        out->tenant_id_lo = 0;
        out->tenant_id_hi = 0xFFFFFFFF;
    }
    else{
        out->tenant_id_lo = ten_lo;
        out->tenant_id_hi = ten_hi;
    }

    //parse ports and vlans from strings
    //default to full range if not present 
    uint16_t lo, hi;
    //set ingress ports, default to full range if not present
    if (parse_input_port_list(y->in_ports,global_port_list, &lo, &hi) < 0){
        out->in_port_lo = 0;
        out->in_port_hi = global_port_list->num_ports - 1;
    }
    else { 
        out->in_port_lo = lo;
        out->in_port_hi = hi;
    }

    //set outer vlan range, default to full range if not present
    if (parse_port_range(y->outer_vlans, &lo, &hi) < 0){
        out->outer_vlan_lo = 0;
        out->outer_vlan_hi = 4095;
    }
    else { 
        out->outer_vlan_lo = lo;
        out->outer_vlan_hi = hi;
    }

    //set inner vlan range, default to full range if not present
    if (parse_port_range(y->inner_vlans, &lo, &hi) < 0){
        out->inner_vlan_lo = 0;
        out->inner_vlan_hi = 4095;
    }
    else { 
        out->inner_vlan_lo = lo;
        out->inner_vlan_hi = hi;
    }

    //set ethertype, "0" is already the wildcard in the back end code
    out->ether_type   = ethertype_from_str(y->ether_type);
    

    //if MAC isn't present, assume all zero
    //if present and successful parse, enable mac match
    out->is_mac_match = false;  
    if(y->src_mac == NULL){
        parse_mac("00:00:00:00:00:00", &out->src_mac);
    }
    else {
        if (parse_mac(y->src_mac, &out->src_mac) < 0)
            return -EINVAL;
        out->is_mac_match = true;
    }

    if (y->dst_mac == NULL){
        parse_mac("00:00:00:00:00:00", &out->dst_mac);
    }
    else  {
        if (parse_mac(y->dst_mac, &out->dst_mac) < 0)
            return -EINVAL;
        out->is_mac_match = true;
    }

    if(y->priority < 1){
        out->priority = 1;
    }
    else{
        out->priority = y->priority;
    }

    //populate action
    return yaml_action_to_policy(&y->action, global_port_list, &out->action);
}


int ppr_acl_load_startup_file(const char *path,
                              ppr_acl_rule_db_t *db,
                              ppr_ports_t *global_port_list)
{
    if (!path || !*path)
        return 0; // nothing to do

    cyaml_err_t err;
    ppr_yaml_acl_root_t *root = NULL;

    static const cyaml_config_t cyaml_cfg = {
        .log_fn = NULL,
        .mem_fn = cyaml_mem,   // or your custom allocator
        .mem_ctx = NULL,
        .flags = CYAML_CFG_DEFAULT,
    };

    err = cyaml_load_file(path, &cyaml_cfg,
                          &ppr_yaml_acl_root_schema,
                          (void **)&root, NULL);
    if (err != CYAML_OK) {
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR,
                "ACL YAML: failed to load '%s': %s\n",
                path, cyaml_strerror(err));
        return -EINVAL;
    }

    int rc = 0;

    /* Apply IPv4 rules */
    for (uint32_t i = 0; i < root->rules.ip4_count; i++) {
        ppr_acl_ip4_rule_cfg_t cfg;
        const ppr_yaml_acl_ip4_rule_t *y = &root->rules.ip4[i];

        PPR_LOG(PPR_LOG_RPC, RTE_LOG_INFO,
                "ACL YAML: processing ip4 rule[%u]: tenant=%s src=%s/%u dst=%s/%u "
                "sports=[%s] dports=[%s] in_ports=[%s] priority=%d\n",
                i,
                y->tenant_ids,
                y->src, y->src_prefix,
                y->dst, y->dst_prefix,
                y->src_ports, y->dst_ports, y->in_ports,
                y->priority);

        rc = yaml_ip4_to_cfg(y, global_port_list, &cfg);
        if (rc < 0) {
            PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR,
                    "ACL YAML: yaml_ip4_to_cfg failed for rule[%u]: rc=%d\n", i, rc);
            goto out;
        }

        rc = ppr_acl_db_add_ip4_rule(db, &cfg, NULL);
        if (rc < 0) {
            PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR,
                    "ACL YAML: ppr_acl_db_add_ip4_rule failed for rule[%u]: rc=%d\n", i, rc);
            goto out;
        }
    }

    /* Apply IPv6 rules */
    for (uint32_t i = 0; i < root->rules.ip6_count; i++) {
        ppr_acl_ip6_rule_cfg_t cfg;
        rc = yaml_ip6_to_cfg(&root->rules.ip6[i],
                             global_port_list, &cfg);
        if (rc < 0)
            goto out;

        rc = ppr_acl_db_add_ip6_rule(db, &cfg, NULL);
        if (rc < 0)
            goto out;
    }

    /* Apply L2 rules */
    for (uint32_t i = 0; i < root->rules.l2_count; i++) {
        ppr_acl_l2_rule_cfg_t cfg;
        rc = yaml_l2_to_cfg(&root->rules.l2[i],
                            global_port_list, &cfg);
        if (rc < 0)
            goto out;

        rc = ppr_acl_db_add_l2_rule(db, &cfg, NULL);
        if (rc < 0)
            goto out;
    }

    PPR_LOG(PPR_LOG_RPC, RTE_LOG_INFO,
            "ACL YAML: loaded %u ip4, %u ip6, %u l2 rules from '%s'\n",
            root->rules.ip4_count,
            root->rules.ip6_count,
            root->rules.l2_count,
            path);

out:
    cyaml_free(&cyaml_cfg, &ppr_yaml_acl_root_schema, root, 0);

    if (rc < 0) {
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR,
                "ACL YAML: error applying rules from '%s'\n", path);
        return rc;
    }

    return 0;
}
// ppr_acl_rpc.c