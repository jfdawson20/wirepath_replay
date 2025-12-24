/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025
 *
Filename: wpr_acl.h
Description: This file implements a L2/L3 packet classification / access control list (ACL) built in top of the DPDK rtc_acl library.
the wpr_acl API contains all the logic to initialize, load, and query ACL rule sets for both IPv4/IPv6 and L2 (MAC address based) flow keys. At its core, 
the rte_acl library handles compiling and optimizing the rule sets into high performance lookup structures. The wpr_acl API wraps this library to provide:
- A per-socket runtime structure with current ACL contexts + epoch
- A build context for off-path ACL compilation and QSBR-safe swapping
- Simple classify APIs taking WPR key structs

A few notes important to understanding the design:
- The ACL rule sets are designed to be rebuilt and swapped at runtime without blocking packet processing. Once an ACL context is built it can't be modified, 
    so to update the rule set a new context is built off-path and then swapped in using RCU mechanisms to ensure no readers are still using the old context.

- while flow keys are defined in other parts of the codebase, the ACL keys used for classification are defined internally here to match the fields needed for ACL
  rules. ACl keys are expected to be flat, packed structs since the ACL engine does raw byte level compares when searching for a match. 
  Conversion functions are provided to convert from wpr_flow_key_t and wpr_l2_flow_key_t to the internal ACL key formats.

- Three separate rte_acl contexts are maintained per-socket: one for IPv4 rules, one for IPv6 rules, and one for L2 (non-IP) rules. This allows 
  us to optimize each context for the specific key types and fields used. Each context has its own build and runtime structures. When performing classification 
  lookups, the user must handle determining which bucket (IPv4, IPv6, L2) to use based on the flow key parsing prior to lookup. 

- the wpr_acl api utilizes two mirrored structures (runtime and build contexts) to manage the ACL rule sets. The runtime context is used by packet processing 
  threads to perform lookups, while the build context is used off-path to compile new rule sets. When a new rule set is ready, 
  it is swapped into the runtime context using RCU mechanisms to ensure safe concurrent access. The main difference between these structs is that the build 
  context contains temporary storage for rules being compiled, while the runtime context contains atomic pointers to the active rte_acl_ctx structures.

- typically the user should not directly access this API beyond initialization and classification calls. the wpr_acl_db module provides a higher level interface
  for managing ACL rule sets,including building, swapping, and maintaining epochs for flow table entries.

Note on endianness / convention. Since the underlying rte_acl library perform most operations using byte level comparisons, its pretty particular about the format 
of keys and rules. The wpr_acl module follows these conventions closely to avoid unnecessary conversions or copies. Specifically, all rules created are expected 
to be in host byte order while all lookup keys are expected to be in network byte order. The rte_acl library handles any necessary conversions internally during 
lookups.
- related to this, the rte_acl library is particular about field offsets and sizes when defining rules. tread carefully if you want to modify the rule field 
  structures to ensure they align with the rte_acl requirements. 
 */

#ifndef WPR_ACL_H
#define WPR_ACL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#include <rte_acl.h>
#include <rte_common.h>
#include <rte_memory.h>
 
#include "wpr_actions.h"
#include "wpr_log.h"
#include "wpr_qsbr.h"
#include "wpr_flowkey.h"
#define WPR_ACL_MAX_RULES 8192




/* -------------------------- WPR ACL API Public Struct Definitions ----------------*/

//stats tracked per ACL rule
typedef struct wpr_acl_worker_rule_stats {
    _Atomic uint64_t new_flows;    //readers increment this per core.
    _Atomic uint64_t closed_flows;
} wpr_acl_worker_rule_stats_t;

// One shard per lcore, per lookup type
typedef struct wpr_acl_stats_shard {
  wpr_acl_worker_rule_stats_t ip4[WPR_ACL_MAX_RULES];
  wpr_acl_worker_rule_stats_t ip6[WPR_ACL_MAX_RULES];
  wpr_acl_worker_rule_stats_t l2[WPR_ACL_MAX_RULES];
} __rte_cache_aligned wpr_acl_stats_shard_t;


typedef struct wpr_acl_rule_stats { 
    _Atomic uint64_t total_flows; 
    _Atomic uint64_t active_flows; 
} wpr_acl_rule_stats_t; 

typedef struct wpr_acl_rule_db_stats {
    wpr_acl_rule_stats_t ip4[WPR_ACL_MAX_RULES];
    wpr_acl_rule_stats_t ip6[WPR_ACL_MAX_RULES];
    wpr_acl_rule_stats_t l2[WPR_ACL_MAX_RULES];
} wpr_acl_rule_db_stats_t;


//policy table structure for holding a list of actions per rule ID. the rte_acl library only returns a rule ID on match,
//so we need to map that back to a full action structure. We maintain separate action tables for IPv4, IPv6, and L2 rules.
typedef struct wpr_acl_policy_tables {
    wpr_policy_action_t ip4_actions[WPR_ACL_MAX_RULES];
    wpr_policy_action_t ip6_actions[WPR_ACL_MAX_RULES];
    wpr_policy_action_t l2_actions[WPR_ACL_MAX_RULES];
} wpr_acl_policy_tables_t;


//main WPR ACL runtime structure used by packet processing threads to perform lookups. ACL contexts are swapped in/out using RCU mechanisms to ensure safe 
// concurrent access. readers must always load the current context pointers atomically before use.
typedef struct wpr_acl_runtime {
    //numa socket ID 
    unsigned int socket_id;
    unsigned int lifetime_build_id;
    unsigned int worker_cores;
    
    // current ACL context pointers
    _Atomic(struct rte_acl_ctx *) ip4_acl_curr;
    _Atomic(struct rte_acl_ctx *) ip6_acl_curr; 
    _Atomic(struct rte_acl_ctx *) l2_acl_curr;

    //current policy tables pointer
    _Atomic(wpr_acl_policy_tables_t *) policy_tables_curr;
    _Atomic(wpr_acl_rule_db_stats_t *) global_stats_curr;     //aggregated stats across all shards
    wpr_acl_stats_shard_t        *stats_shards;        //per-lcore stats shards


    //pointer to global epoch tracker struct 
    wpr_global_policy_epoch_t     *epoch_ctx;   
    
    //qsbr support 
    wpr_rcu_ctx_t                 *qsbr_ctx;
    struct rte_rcu_qsbr_dq        *acl_ctx_qsbr_dq;
    struct rte_rcu_qsbr_dq        *acl_tables_qsbr_dq;
    struct rte_rcu_qsbr_dq        *acl_stats_qsbr_dq;
    uint32_t                      qsbr_max_reclaim_size;

} wpr_acl_runtime_t;


//this is the build struct used by the WPR ACL API to compile new rule sets off-path. once a new rule set is built, it can be swapped into the runtime 
// structure using RCU mechanisms.
typedef struct wpr_acl_build_ctx {
    //numa socket ID
    int                 socket_id;

    //pointers to ACL build contexts, these do not have to be atomic since they are only used off-path
    struct rte_acl_ctx *ip4_acl_build;
    struct rte_acl_ctx *ip6_acl_build; 
    struct rte_acl_ctx *l2_acl_build;

    //build-side policy tables pointer
    wpr_acl_policy_tables_t *tables_build; 
    wpr_acl_rule_db_stats_t *global_stats_build;     //aggregated stats across all shards

    //rule counts in this build context 
    uint32_t            ip4_rule_count;
    uint32_t            ip6_rule_count; 
    uint32_t            l2_rule_count;
} wpr_acl_build_ctx_t;

//This structure defines the configuration for an IPv4 ACL rule to be added to a build context.
typedef struct wpr_acl_ip4_rule_cfg {
    uint32_t tenant_id_lo;
    uint32_t tenant_id_hi;

    /* IPv4 5-tuple */
    uint32_t src_ip;      
    uint8_t  src_prefix;  
    uint32_t dst_ip;      
    uint8_t  dst_prefix; 

    uint16_t src_port_lo;
    uint16_t src_port_hi;
    uint16_t dst_port_lo;
    uint16_t dst_port_hi;

    uint8_t  proto;       

    uint16_t in_port_lo;  
    uint16_t in_port_hi;

    int32_t  priority;    /* higher wins */
    uint32_t rule_id;     /* app-visible id */

    wpr_policy_action_t action;
} wpr_acl_ip4_rule_cfg_t;


//This structure defines the configuration for an IPv6 ACL rule to be added to a build context.
typedef struct wpr_acl_ip6_rule_cfg {
    uint32_t tenant_id_lo;
    uint32_t tenant_id_hi;

    /* IPv6 5-tuple (addresses are raw network-order bytes) */
    uint8_t  src_ip[16];   /* network order */
    uint8_t  dst_ip[16];   /* network order */
    uint8_t  src_prefix;   /* 0–128 */
    uint8_t  dst_prefix;   /* 0–128 */

    uint16_t src_port_lo;  /* be16 range */
    uint16_t src_port_hi;
    uint16_t dst_port_lo;
    uint16_t dst_port_hi;

    uint8_t  proto;        /* 0 = any, else IPPROTO_* */

    uint16_t in_port_lo;   /* ingress port range, 0 = any */
    uint16_t in_port_hi;

    int32_t  priority;     /* higher wins */
    uint32_t rule_id;      /* app-visible id */

    wpr_policy_action_t action;
} wpr_acl_ip6_rule_cfg_t;

//This structure defines the configuration for an L2 (non-IP) ACL rule to be added to a build context.    
typedef struct wpr_acl_l2_rule_cfg {
    uint32_t tenant_id_lo;
    uint32_t tenant_id_hi;

    uint16_t in_port_lo;
    uint16_t in_port_hi;

    uint16_t outer_vlan_lo;
    uint16_t outer_vlan_hi;
    uint16_t inner_vlan_lo;
    uint16_t inner_vlan_hi;

    uint16_t ether_type;  /* 0 = any */

    uint8_t  is_mac_match; /* 0 = ignore MACs, 1 = exact src/dst */
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;

    int32_t  priority;
    uint32_t rule_id;

    wpr_policy_action_t action;
} wpr_acl_l2_rule_cfg_t;

/* --------------------------------------------------------------------- */
/* Public API                                                            */
/* --------------------------------------------------------------------- */

//lifecycle management
int  wpr_acl_runtime_init(wpr_acl_runtime_t *rt, int socket_id, wpr_rcu_ctx_t *rcu_ctx, wpr_global_policy_epoch_t *ge, 
    uint32_t reclaim_trigger,uint32_t max_reclaim, unsigned int num_workers);
void wpr_acl_runtime_deinit(wpr_acl_runtime_t *rt);
void wpr_acl_qsbr_reclaim(wpr_acl_runtime_t *rt);
int wpr_acl_stats_accumulator(wpr_acl_runtime_t *rt);

//context build management
int  wpr_acl_build_begin(wpr_acl_build_ctx_t *bld, const wpr_acl_runtime_t *rt, uint32_t max_ip4_rules, uint32_t max_ip6_rules, uint32_t max_l2_rules);
int  wpr_acl_build_add_ip4_rule(wpr_acl_build_ctx_t *bld, const wpr_acl_ip4_rule_cfg_t *rcfg);
int  wpr_acl_build_add_ip6_rule(wpr_acl_build_ctx_t *bld, const wpr_acl_ip6_rule_cfg_t *rcfg);
int  wpr_acl_build_add_l2_rule(wpr_acl_build_ctx_t *bld, const wpr_acl_l2_rule_cfg_t *rcfg);
int  wpr_acl_build_commit(wpr_acl_runtime_t *rt, wpr_acl_build_ctx_t *bld);
void wpr_acl_build_abort(wpr_acl_build_ctx_t *bld);




//classification functions - used by readers / packet data path
//IPV4 / IPV6 classification - shared lookup due to unified flow key format
int wpr_acl_classify_ip(const wpr_acl_runtime_t *rt,
                        const wpr_flow_key_t    *key,
                        uint16_t                 in_port,
                        wpr_policy_action_t     *res);

// L2 classification - separate from IP due to different flow key format
int wpr_acl_classify_l2(const wpr_acl_runtime_t *rt,
                        const wpr_l2_flow_key_t *l2_key,
                        wpr_policy_action_t     *res);


//debug functions 
bool wpr_acl_ip4_rule_matches_semantic(const wpr_acl_ip4_rule_cfg_t *r, const wpr_flow_key_t *fk, uint16_t in_port);
bool wpr_acl_ip6_rule_matches_semantic(const wpr_acl_ip6_rule_cfg_t *r, const wpr_flow_key_t *fk, uint16_t in_port);
bool wpr_acl_l2_rule_matches_semantic(const wpr_acl_l2_rule_cfg_t *r, const wpr_l2_flow_key_t *fk, uint16_t in_port);
void wpr_acl_print_ip4_rule(const wpr_acl_ip4_rule_cfg_t *r);
void wpr_acl_print_ip6_rule(const wpr_acl_ip6_rule_cfg_t *r);
void wpr_acl_print_l2_rule(const wpr_acl_l2_rule_cfg_t *r);
void wpr_acl_hexdump(const char *tag, const void *p, size_t len);
void wpr_acl_debug_dump_ip4_rule(const struct rte_acl_rule *r);
void wpr_acl_debug_dump_ip6_rule(const struct rte_acl_rule *r);
void wpr_acl_debug_dump_l2_rule(const struct rte_acl_rule *r);


static inline void wpr_format_mac(const struct rte_ether_addr *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1],
             mac->addr_bytes[2], mac->addr_bytes[3],
             mac->addr_bytes[4], mac->addr_bytes[5]);
}

static inline const char * wpr_proto_to_str(uint8_t proto)
{
    switch (proto) {
    case 0:             return "any";
    case IPPROTO_TCP:   return "tcp";
    case IPPROTO_UDP:   return "udp";
    case IPPROTO_ICMP:  return "icmp";
    case IPPROTO_ICMPV6:return "icmpv6";
    default:            return "other";
    }
}

static inline const char *wpr_ethertype_to_str(uint16_t et)
{
    switch (et) {
    case 0x0000: return "any";
    case 0x0800: return "ipv4";
    case 0x86DD: return "ipv6";
    case 0x0806: return "arp";
    default:     return "other";
    }
}



#endif /* WPR_ACL_H */

