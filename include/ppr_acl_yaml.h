#ifndef PPR_ACL_YAML_H
#define PPR_ACL_YAML_H

#include <stdint.h>
#include <stdbool.h>
#include <cyaml/cyaml.h>

#include "ppr_acl.h"   
#include "ppr_acl_db.h" 
#include "ppr_ports.h"  

typedef struct {
    char       *default_policy;   // "FORWARD" / "DROP" / etc.
} ppr_yaml_acl_action_t;

typedef struct {
    char  *tenant_ids;
    char    *src;         // "10.0.0.0"
    uint8_t  src_prefix;
    char    *dst;         // "192.168.1.10"
    uint8_t  dst_prefix;

    char    *src_ports;   // "0:65535", "80", "100:200"
    char    *dst_ports;
    char    *in_ports;

    char    *proto;       // "any","tcp","udp","icmp"

    int32_t  priority;

    ppr_yaml_acl_action_t action;
} ppr_yaml_acl_ip4_rule_t;

typedef struct {
    char    *tenant_ids;
    char    *src;         // "2001:db8::..."
    uint8_t  src_prefix;
    char    *dst;
    uint8_t  dst_prefix;

    char    *src_ports;   // "0:65535", "80", "100:200"
    char    *dst_ports;
    char    *in_ports;

    char    *proto;       // "any","tcp","udp","icmp"

    int32_t  priority;

    ppr_yaml_acl_action_t action;
} ppr_yaml_acl_ip6_rule_t;

typedef struct {
    char    *tenant_ids;
    char    *in_ports;     // "0", "1:10"
    char *outer_vlans;  // "0", "100", "100:200"
    char *inner_vlans;
    char    *ether_type;   // "any","ipv4","ipv6","arp"
    char    *src_mac;      // "aa:bb:cc:dd:ee:ff"
    char    *dst_mac;
    int32_t  priority;

    ppr_yaml_acl_action_t action;
} ppr_yaml_acl_l2_rule_t;

typedef struct {
    ppr_yaml_acl_ip4_rule_t *ip4;
    uint32_t                  ip4_count;

    ppr_yaml_acl_ip6_rule_t *ip6;
    uint32_t                 ip6_count;

    ppr_yaml_acl_l2_rule_t  *l2;
    uint32_t                 l2_count;
} ppr_yaml_acl_rules_t;

typedef struct {
    ppr_yaml_acl_rules_t rules;
} ppr_yaml_acl_root_t;

/* Main entrypoint: parse file, add rules into db. */
int ppr_acl_load_startup_file(const char *path,
                              ppr_acl_rule_db_t *db,
                              ppr_ports_t *global_port_list);

#endif /* PPR_ACL_YAML_H */