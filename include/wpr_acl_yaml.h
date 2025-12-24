#ifndef WPR_ACL_YAML_H
#define WPR_ACL_YAML_H

#include <stdint.h>
#include <stdbool.h>
#include <cyaml/cyaml.h>

#include "wpr_acl.h"   
#include "wpr_acl_db.h" 
#include "wpr_ports.h"  

typedef struct {
    char       *default_policy;   // "FORWARD" / "DROP" / etc.
} wpr_yaml_acl_action_t;

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

    wpr_yaml_acl_action_t action;
} wpr_yaml_acl_ip4_rule_t;

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

    wpr_yaml_acl_action_t action;
} wpr_yaml_acl_ip6_rule_t;

typedef struct {
    char    *tenant_ids;
    char    *in_ports;     // "0", "1:10"
    char *outer_vlans;  // "0", "100", "100:200"
    char *inner_vlans;
    char    *ether_type;   // "any","ipv4","ipv6","arp"
    char    *src_mac;      // "aa:bb:cc:dd:ee:ff"
    char    *dst_mac;
    int32_t  priority;

    wpr_yaml_acl_action_t action;
} wpr_yaml_acl_l2_rule_t;

typedef struct {
    wpr_yaml_acl_ip4_rule_t *ip4;
    uint32_t                  ip4_count;

    wpr_yaml_acl_ip6_rule_t *ip6;
    uint32_t                 ip6_count;

    wpr_yaml_acl_l2_rule_t  *l2;
    uint32_t                 l2_count;
} wpr_yaml_acl_rules_t;

typedef struct {
    char *pcap_filepath;   // "/path/to/file.pcap"
} wpr_yaml_template_t;

typedef struct {
    wpr_yaml_template_t  template;
    wpr_yaml_acl_rules_t rules;
} wpr_yaml_acl_root_t;

/* Main entrypoint: parse file, add rules into db. */
int wpr_acl_load_startup_file(const char *path,
                              wpr_acl_rule_db_t *db,
                              wpr_ports_t *global_port_list,
                              char **pcap_template_out);

#endif /* WPR_ACL_YAML_H */