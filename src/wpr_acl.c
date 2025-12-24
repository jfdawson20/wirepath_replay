/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025
 *
Filename: wpr_acl.c
Description: This file implements a L2/L3 packet classification / access control list (ACL) built in top of the DPDK rtc_acl library.
the wpr_acl API contains all the logic to initialize, load, and query ACL rule sets for both IPv4/IPv6 and L2 (MAC address based) flow keys. At its core, 
the rte_acl library handles compiling and optimizing the rule sets into high performance lookup structures. The wpr_acl API wraps this library to provide:
- A per-socket runtime structure with current ACL contexts + epoch
- A build context for off-path ACL compilation and QSBR-safe swapping
- Simple classify APIs taking wpr key structs

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

Note on edianess / convention. Since the underlying rte_acl library perform most opertions using byte level comparisons, its pretty particular about the format 
of keys and rules. The wpr_acl module follows these conventions closely to avoid unnecessary conversions or copies. Specifically, all rules created are expected 
to be in host byte order while all lookup keys are expected to be in network byte order. The rte_acl library handles any necessary conversions internally during 
lookups.
- related to this, the rte_acl library is particular about field offsets and sizes when defining rules. tread carefully if you want to modify the rule field 
  structures to ensure they align with the rte_acl requirements. 
 */


#include "wpr_acl.h"

#include <string.h>
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_errno.h>



/* ------------------------------ rte_acl rule field definitions -------------------------------------------*/
//in order to create ACL rules and perform lookups, we need to define the fields present in our ACL keys.
//the enums below define the field indices for IPv4, IPv6, and L2 ACL keys respectively.

//ipv4
typedef enum wpr_acl_ip4_fields {
    WPR_ACL_IP4_FIELD_PROTO = 0,     
    WPR_ACL_IP4_FIELD_SRC_IP,        
    WPR_ACL_IP4_FIELD_DST_IP,         
    WPR_ACL_IP4_FIELD_SRC_PORT,     
    WPR_ACL_IP4_FIELD_DST_PORT,     
    WPR_ACL_IP4_FIELD_TENANT,        
    WPR_ACL_IP4_FIELD_IN_PORT,         
    WPR_ACL_IP4_NUM_FIELDS
} wpr_acl_ip4_fields_t;

//ipv6
typedef enum wpr_acl_ip6_fields {
    WPR_ACL_IP6_FIELD_PROTO = 0,

    WPR_ACL_IP6_FIELD_SRC_IP0,
    WPR_ACL_IP6_FIELD_SRC_IP1,
    WPR_ACL_IP6_FIELD_SRC_IP2,
    WPR_ACL_IP6_FIELD_SRC_IP3,

    WPR_ACL_IP6_FIELD_DST_IP0,
    WPR_ACL_IP6_FIELD_DST_IP1,
    WPR_ACL_IP6_FIELD_DST_IP2,
    WPR_ACL_IP6_FIELD_DST_IP3,

    WPR_ACL_IP6_FIELD_SRC_PORT,
    WPR_ACL_IP6_FIELD_DST_PORT,
    
    WPR_ACL_IP6_FIELD_TENANT,
    WPR_ACL_IP6_FIELD_IN_PORT,

    WPR_ACL_IP6_NUM_FIELDS
} wpr_acl_ip6_fields_t;
    
//l2
typedef enum wpr_acl_l2_fields {
    WPR_ACL_L2_FIELD_TAG = 0,
    WPR_ACL_L2_FIELD_TENANT,
    WPR_ACL_L2_FIELD_OUTER_VLAN,
    WPR_ACL_L2_FIELD_INNER_VLAN,
    WPR_ACL_L2_FIELD_ETHER_TYPE,
    WPR_ACL_L2_FIELD_IN_PORT,
    WPR_ACL_L2_FIELD_SRC_MAC_HI,
    WPR_ACL_L2_FIELD_DST_MAC_HI,
    WPR_ACL_L2_FIELD_SRC_MAC_LO,
    WPR_ACL_L2_FIELD_DST_MAC_LO,
    WPR_ACL_L2_NUM_FIELDS
} wpr_acl_l2_fields_t;


//the following structs define the internal ACL key formats used for rule creation and lookups. the rte_acl library is particular about how fields 
//are laid out in memory, so these structs must be carefully defined to match those requirements. they must be packed to avoid any compiler-added padding.
//the field offsets used later int he field definitions must match these structs exactly.

//ipv4 internal key format
typedef struct wpr_acl_ip4_key_internal {
    uint8_t  proto;
    uint8_t  pad0[3];      // offset 0
    uint32_t src_ip;       // offset 4 (word 1)
    uint32_t dst_ip;       // offset 8 (word 2)
    uint32_t src_port;     // offset 12 (word 3)
    uint32_t dst_port;     // offset 16 (word 4)
    uint32_t tenant_id;    // offset 20 (word 5)
    uint32_t in_port;      // offset 24 (word 6)
} __rte_packed wpr_acl_ip4_key_internal_t;



//ipv6 internal key format
typedef struct wpr_acl_ip6_key_internal {
    uint8_t  proto;
    uint8_t  pad0[3];

    uint32_t src_ip[4];    /* 4 x 32 bits = 128-bit src */
    uint32_t dst_ip[4];   /*  4 x 32 bits = 128-bit dst */

    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tenant_id;
    uint32_t in_port;

} __rte_packed wpr_acl_ip6_key_internal_t;


typedef struct wpr_acl_l2_key_internal {
    uint8_t  l2_tag;
    uint8_t  pad0[3];

    uint32_t tenant_id;

    uint16_t outer_vlan;
    uint16_t inner_vlan;

    uint16_t ether_type;
    uint16_t in_port;

    uint16_t src_mac_hi;
    uint16_t dst_mac_hi;

    uint32_t src_mac_lo;
    uint32_t dst_mac_lo;
} __rte_packed wpr_acl_l2_key_internal_t;


//The following arrays define the field definitions used by the rte_acl library for each ACL key type. these definitions specify the type, size, offset,
//and input index for each field in the ACL keys. they must match the internal key structs defined above exactly.This is also what specifies what type of 
//matching (range, mask, bitmask) is used for each field during lookups.
//note - field_index must match the enum values defined earlier for each field.
//note - input_index specifies which input word the field is located in. the rte_acl library processes keys in 32-bit words, so fields must be mapped accordingly.

//IPv4 field definitions
static const struct rte_acl_field_def wpr_acl_ip4_defs[WPR_ACL_IP4_NUM_FIELDS] = {
    [WPR_ACL_IP4_FIELD_PROTO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = WPR_ACL_IP4_FIELD_PROTO,
        .input_index = 0,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, proto),
    },
    [WPR_ACL_IP4_FIELD_SRC_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_SRC_IP,
        .input_index = 1,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, src_ip),
    },
    [WPR_ACL_IP4_FIELD_DST_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_DST_IP,
        .input_index = 2,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, dst_ip),
    },
    [WPR_ACL_IP4_FIELD_SRC_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_SRC_PORT,
        .input_index = 3,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, src_port),
    },
    [WPR_ACL_IP4_FIELD_DST_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_DST_PORT,
        .input_index = 4,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, dst_port),
    },
    [WPR_ACL_IP4_FIELD_TENANT] = {
        . type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_TENANT,
        .input_index = 5,
        .offset      = offsetof(wpr_acl_ip4_key_internal_t, tenant_id),
    },
    [WPR_ACL_IP4_FIELD_IN_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP4_FIELD_IN_PORT,
        . input_index = 6,
        . offset      = offsetof(wpr_acl_ip4_key_internal_t, in_port),
    },
};

//ipv6 field definitions
static const struct rte_acl_field_def wpr_acl_ip6_defs[WPR_ACL_IP6_NUM_FIELDS] = {

    /* Proto: byte in word 0 */
    [WPR_ACL_IP6_FIELD_PROTO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = WPR_ACL_IP6_FIELD_PROTO,
        .input_index = 0,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, proto),
    },

    /* src IPv6: four MASK fields of 32 bits each (words 1–4) */
    [WPR_ACL_IP6_FIELD_SRC_IP0] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_SRC_IP0,
        .input_index = 1,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, src_ip[0]),
    },
    [WPR_ACL_IP6_FIELD_SRC_IP1] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_SRC_IP1,
        .input_index = 2,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, src_ip[1]),
    },
    [WPR_ACL_IP6_FIELD_SRC_IP2] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_SRC_IP2,
        .input_index = 3,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, src_ip[2]),
    },
    [WPR_ACL_IP6_FIELD_SRC_IP3] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_SRC_IP3,
        .input_index = 4,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, src_ip[3]),
    },

    /* dst IPv6: four MASK fields of 32 bits each (words 5–8) */
    [WPR_ACL_IP6_FIELD_DST_IP0] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_DST_IP0,
        .input_index = 5,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, dst_ip[0]),
    },
    [WPR_ACL_IP6_FIELD_DST_IP1] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_DST_IP1,
        .input_index = 6,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, dst_ip[1]),
    },
    [WPR_ACL_IP6_FIELD_DST_IP2] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_DST_IP2,
        .input_index = 7,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, dst_ip[2]),
    },
    [WPR_ACL_IP6_FIELD_DST_IP3] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_DST_IP3,
        .input_index = 8,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, dst_ip[3]),
    },

    /* Ports live in word 9 */
    [WPR_ACL_IP6_FIELD_SRC_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_IP6_FIELD_SRC_PORT,
        .input_index = 9,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, src_port),
    },
    [WPR_ACL_IP6_FIELD_DST_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_IP6_FIELD_DST_PORT,
        .input_index = 9,  /* same 32-bit word as src_port */
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, dst_port),
    },

    /* tenant_id: word 10 */
    [WPR_ACL_IP6_FIELD_TENANT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_TENANT,
        .input_index = 10,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, tenant_id),
    },

    /* in_port: word 11 */
    [WPR_ACL_IP6_FIELD_IN_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_IP6_FIELD_IN_PORT,
        .input_index = 11,
        .offset      = offsetof(wpr_acl_ip6_key_internal_t, in_port),
    },
};


static const struct rte_acl_field_def wpr_acl_l2_defs[WPR_ACL_L2_NUM_FIELDS] = {
    [WPR_ACL_L2_FIELD_TAG] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = WPR_ACL_L2_FIELD_TAG,
        .input_index = 0,
        .offset      = offsetof(wpr_acl_l2_key_internal_t, l2_tag),
    },
    [WPR_ACL_L2_FIELD_TENANT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_L2_FIELD_TENANT,
        .input_index = 1, // word1
        .offset      = offsetof(wpr_acl_l2_key_internal_t, tenant_id),
    },
    [WPR_ACL_L2_FIELD_OUTER_VLAN] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_OUTER_VLAN,
        .input_index = 2, // word2
        .offset      = offsetof(wpr_acl_l2_key_internal_t, outer_vlan),
    },
    [WPR_ACL_L2_FIELD_INNER_VLAN] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_INNER_VLAN,
        .input_index = 2, // same word2
        .offset      = offsetof(wpr_acl_l2_key_internal_t, inner_vlan),
    },
    [WPR_ACL_L2_FIELD_ETHER_TYPE] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_ETHER_TYPE,
        .input_index = 3, // word3
        .offset      = offsetof(wpr_acl_l2_key_internal_t, ether_type),
    },
    [WPR_ACL_L2_FIELD_IN_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_IN_PORT,
        .input_index = 3, // same word3
        .offset      = offsetof(wpr_acl_l2_key_internal_t, in_port),
    },  
    [WPR_ACL_L2_FIELD_SRC_MAC_HI] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_SRC_MAC_HI,
        .input_index = 4, // word4
        .offset      = offsetof(wpr_acl_l2_key_internal_t, src_mac_hi),
    },
    [WPR_ACL_L2_FIELD_DST_MAC_HI] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint16_t),
        .field_index = WPR_ACL_L2_FIELD_DST_MAC_HI,
        .input_index = 4, // same word4
        .offset      = offsetof(wpr_acl_l2_key_internal_t, dst_mac_hi),
    },
    [WPR_ACL_L2_FIELD_SRC_MAC_LO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_L2_FIELD_SRC_MAC_LO,
        .input_index = 5, // word5 (20–23)
        .offset      = offsetof(wpr_acl_l2_key_internal_t, src_mac_lo),
    },
    [WPR_ACL_L2_FIELD_DST_MAC_LO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint32_t),
        .field_index = WPR_ACL_L2_FIELD_DST_MAC_LO,
        .input_index = 6, // word6 (24–27)
        .offset      = offsetof(wpr_acl_l2_key_internal_t, dst_mac_lo),
    },

};

_Static_assert(offsetof(wpr_acl_l2_key_internal_t, ether_type) == 12, "ether_type offset mismatch");
_Static_assert(offsetof(wpr_acl_l2_key_internal_t, in_port)    == 14, "in_port offset mismatch");
_Static_assert(offsetof(wpr_acl_l2_key_internal_t, src_mac_hi) == 16, "src_mac_hi offset mismatch");
_Static_assert(offsetof(wpr_acl_l2_key_internal_t, dst_mac_hi) == 18, "dst_mac_hi offset mismatch");
_Static_assert(offsetof(wpr_acl_l2_key_internal_t, src_mac_lo) == 20, "src_mac_lo offset mismatch");
_Static_assert(offsetof(wpr_acl_l2_key_internal_t, dst_mac_lo) == 24, "dst_mac_lo offset mismatch");




/* ------------------------------ Debug Print / Helpers --------------------------------------------- */
// the next section contains various debug print functions and helpers for debugging acl functionality. 


/**
* Dump the fields of an IPv4 ACL key for debugging. Takes a internal ACL key and prints each field's offset, size, and raw byte values.
* This is useful for verifying that keys are being constructed correctly and that field definitions match expectations.
* @param k Pointer to the internal IPv4 ACL key to dump.
**/
static void wpr_acl_debug_dump_ip4_key_fields(const wpr_acl_ip4_key_internal_t *k)
{
    const uint8_t *base = (const uint8_t *)k;

    for (int i = 0; i < WPR_ACL_IP4_NUM_FIELDS; i++) {
        const struct rte_acl_field_def *fd = &wpr_acl_ip4_defs[i];
        const uint8_t *p = base + fd->offset;

        char line[128];
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos,
                        "IP4_KEY_FIELD[%d] offset=%u size=%u bytes: ",
                        i, fd->offset, fd->size);
        for (uint32_t b = 0; b < fd->size && pos < (int)sizeof(line) - 3; b++) {
            pos += snprintf(line + pos, sizeof(line) - pos,
                            "%02x ", p[b]);
        }
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "%s\n", line);
    }
}

/** 
* Dump the fields of an IPv6 ACL key for debugging. Takes a internal ACL key and prints each field's offset, size, and raw byte values.
* This is useful for verifying that keys are being constructed correctly and that field definitions match expectations.
* @param k Pointer to the internal IPv6 ACL key to dump.
**/
static void wpr_acl_debug_dump_ip6_key_fields(const wpr_acl_ip6_key_internal_t *k)
{
    const uint8_t *base = (const uint8_t *)k;

    for (int i = 0; i < WPR_ACL_IP6_NUM_FIELDS; i++) {
        const struct rte_acl_field_def *fd = &wpr_acl_ip6_defs[i];
        const uint8_t *p = base + fd->offset;

        char line[128];
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos,
                        "IP6_KEY_FIELD[%d] offset=%u size=%u bytes: ",
                        i, fd->offset, fd->size);
        for (uint32_t b = 0; b < fd->size && pos < (int)sizeof(line) - 3; b++) {
            pos += snprintf(line + pos, sizeof(line) - pos,
                            "%02x ", p[b]);
        }
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "%s\n", line);
    }
}


/** 
* Dump the fields of an L2 ACL key for debugging. Takes a internal ACL key and prints each field's offset, size, and raw byte values.
* This is useful for verifying that keys are being constructed correctly and that field definitions match expectations.
* @param k Pointer to the internal L2 ACL key to dump.
**/
static void wpr_acl_debug_dump_l2_key_fields(const wpr_acl_l2_key_internal_t *k)
{
    const uint8_t *base = (const uint8_t *)k;

    for (int i = 0; i < WPR_ACL_L2_NUM_FIELDS; i++) {
        const struct rte_acl_field_def *fd = &wpr_acl_l2_defs[i];
        const uint8_t *p = base + fd->offset;

        char line[128];
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos,
                        "L2_KEY_FIELD[%d] offset=%u size=%u bytes: ",
                        i, fd->offset, fd->size);
        for (uint32_t b = 0; b < fd->size && pos < (int)sizeof(line) - 3; b++) {
            pos += snprintf(line + pos, sizeof(line) - pos,
                            "%02x ", p[b]);
        }
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "%s\n", line);
    }
}

void wpr_acl_debug_dump_ip4_rule(const struct rte_acl_rule *r) {
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "IPv4 rule debug dump\n");
    for (int i = 0; i < WPR_ACL_IP4_NUM_FIELDS; i++) {
        const struct rte_acl_field *f = &r->field[i];
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                " field[%d]: val u32=0x%08x u16=0x%04x u8=0x%02x  "
                "mask_range u32=%u u16=%u u8=%u\n",
                i,
                f->value.u32, f->value.u16, f->value.u8,
                f->mask_range.u32, f->mask_range.u16, f->mask_range.u8);
    }
}

void wpr_acl_debug_dump_ip6_rule(const struct rte_acl_rule *r) {
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "IPv6 rule debug dump\n");
    for (int i = 0; i < WPR_ACL_IP6_NUM_FIELDS; i++) {
        const struct rte_acl_field *f = &r->field[i];
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                " field[%d]: val u32=0x%08x u16=0x%04x u8=0x%02x  "
                "mask_range u32=%u u16=%u u8=%u\n",
                i,
                f->value.u32, f->value.u16, f->value.u8,
                f->mask_range.u32, f->mask_range.u16, f->mask_range.u8);
    }
}

void wpr_acl_debug_dump_l2_rule(const struct rte_acl_rule *r) {
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "L2 rule debug dump\n");
    for (int i = 0; i < WPR_ACL_L2_NUM_FIELDS; i++) {
        const struct rte_acl_field *f = &r->field[i];
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                " field[%d]: val u32=0x%08x u16=0x%04x u8=0x%02x  "
                "mask_range u32=%u u16=%u u8=%u\n",
                i,
                f->value.u32, f->value.u16, f->value.u8,
                f->mask_range.u32, f->mask_range.u16, f->mask_range.u8);
    }
}

/** 
* Helper function to check if an IPv4 address matches a rule prefix. NOT used in lookups, only for semantic matching checks.
* @param key_ip The IPv4 address from the flow key (in host byte order).
* @param rule_ip The IPv4 address from the ACL rule (in host byte order).
* @param prefix The prefix length of the rule (0-32).
* @return true if the key_ip matches the rule_ip/prefix, false otherwise.
**/
static bool wpr_ip4_addr_matches_host(uint32_t key_ip, uint32_t rule_ip, uint8_t prefix)
{
    if (prefix == 0)
        return true;

    uint32_t mask = (prefix == 32) ? 0xffffffffu : ~((1u << (32 - prefix)) - 1u);

    return (key_ip & mask) == (rule_ip & mask);
}

/** 
* Helper function to check if an IPv6 address matches a rule prefix. NOT used in lookups, only for semantic matching checks.
* @param key_ip The IPv6 address from the flow key (array of 4 uint32_t in host byte order).
* @param rule_ip The IPv6 address from the ACL rule (array of 4 uint32_t in host byte order).
* @param prefix The prefix length of the rule (0-128).
* @return true if the key_ip matches the rule_ip/prefix, false otherwise.   
**/
static bool wpr_ip6_addr_matches_host(const uint32_t key_ip[4],
                                   const uint32_t rule_ip[4],
                                   uint8_t        prefix)
{
    if (prefix == 0)
        return true;

    int full_words = prefix / 32;
    int remaining_bits = prefix % 32;

    for (int i = 0; i < full_words; i++) {
        if (key_ip[i] != rule_ip[i])
            return false;
    }

    if (remaining_bits > 0) {
        uint32_t mask = ~((1u << (32 - remaining_bits)) - 1u);
        if ((key_ip[full_words] & mask) != (rule_ip[full_words] & mask))
            return false;
    }

    return true;
}


/** 
* Check if an IPv4 ACL rule matches a given flow key and ingress port semantically. NOT used in lookups, only for semantic matching checks.
* @param r Pointer to the IPv4 ACL rule configuration.
* @param fk Pointer to the flow key to check.
* @param in_port The ingress port number (in host byte order).
* @return true if the rule matches the flow key and ingress port, false otherwise.
**/
bool wpr_acl_ip4_rule_matches_semantic(const wpr_acl_ip4_rule_cfg_t *r,
                                  const wpr_flow_key_t        *fk,
                                  uint16_t                     in_port)
{
    const wpr_flow_key_v4_t *v4 = &fk->ip.v4;

    // tenant exact match 
    if (fk->tenant_id < r->tenant_id_lo || fk->tenant_id > r->tenant_id_hi)
        return false;

    // ingress port range in host order
    if (in_port < r->in_port_lo || in_port > r->in_port_hi)
        return false;

    // IPv4 src/dst in host byte order 
    if (!wpr_ip4_addr_matches_host(v4->src_ip, r->src_ip, r->src_prefix))
        return false;

    if (!wpr_ip4_addr_matches_host(v4->dst_ip, r->dst_ip, r->dst_prefix))
        return false;

    // ports in host byte order 
    if (v4->src_port < r->src_port_lo || v4->src_port > r->src_port_hi)
        return false;

    if (v4->dst_port < r->dst_port_lo || v4->dst_port > r->dst_port_hi)
        return false;

    // proto: 0 = wildcard 
    if (r->proto != 0 && r->proto != v4->proto)
        return false;

    return true;
}


/**
* Check if an IPv6 ACL rule matches a given flow key and ingress port semantically. NOT used in lookups, only for semantic matching checks.
* @param r Pointer to the IPv6 ACL rule configuration.
* @param fk Pointer to the flow key to check.
* @param in_port The ingress port number (in host byte order).
* @return true if the rule matches the flow key and ingress port, false otherwise.
**/
bool wpr_acl_ip6_rule_matches_semantic(const wpr_acl_ip6_rule_cfg_t *r,
                                  const wpr_flow_key_t        *fk,
                                  uint16_t                     in_port)
{
    const wpr_flow_key_v6_t *v6 = &fk->ip.v6;

    // tenant exact match 
    if (fk->tenant_id < r->tenant_id_lo || fk->tenant_id > r->tenant_id_hi)
        return false;

    // ingress port range in host order
    if (in_port < r->in_port_lo || in_port > r->in_port_hi)
        return false;

    // IPv6 src/dst in host byte order 
    if (!wpr_ip6_addr_matches_host((uint32_t *)&v6->src_ip[0], (uint32_t *)&r->src_ip, r->src_prefix))
        return false;

    if (!wpr_ip6_addr_matches_host((uint32_t *)&v6->dst_ip[0], (uint32_t *)&r->dst_ip, r->dst_prefix))
        return false;

    // ports in host byte order 
    if (v6->src_port < r->src_port_lo || v6->src_port > r->src_port_hi)
        return false;

    if (v6->dst_port < r->dst_port_lo || v6->dst_port > r->dst_port_hi)
        return false;

    // proto: 0 = wildcard 
    if (r->proto != 0 && r->proto != v6->proto)
        return false;

    return true;
}

/** 
* Check if an L2 ACL rule matches a given flow key and ingress port semantically. NOT used in lookups, only for semantic matching checks.
* @param r Pointer to the L2 ACL rule configuration.
* @param fk Pointer to the flow key to check.
* @param in_port The ingress port number (in host byte order).
* @return true if the rule matches the flow key and ingress port, false otherwise.
**/
bool wpr_acl_l2_rule_matches_semantic(const wpr_acl_l2_rule_cfg_t *r,
                                 const wpr_l2_flow_key_t     *fk,
                                 uint16_t                     in_port)
{
    /* tenant exact match */
    if (fk->tenant_id < r->tenant_id_lo || fk->tenant_id > r->tenant_id_hi)
        return false;

    /* ingress port range in host order */
    if (in_port < r->in_port_lo || in_port > r->in_port_hi)
        return false;

    /* outer VLAN */
    if (fk->outer_vlan < r->outer_vlan_lo || fk->outer_vlan > r->outer_vlan_hi)
        return false;

    /* inner VLAN */
    if (fk->inner_vlan < r->inner_vlan_lo || fk->inner_vlan > r->inner_vlan_hi)
        return false;

    /* MACs only participate if is_mac_match is enabled */
    if (r->is_mac_match) {
        if (memcmp(fk->src.addr_bytes, r->src_mac.addr_bytes, RTE_ETHER_ADDR_LEN) != 0)
            return false;

        if (memcmp(fk->dst.addr_bytes, r->dst_mac.addr_bytes, RTE_ETHER_ADDR_LEN) != 0)
            return false;
    }

    /* ether type: 0 = wildcard */
    if (r->ether_type != 0 && fk->ether_type != r->ether_type)
        return false;

    return true;
}


/** 
* Dump a hex representation of a memory region to the log.
* @param tag A string tag to prefix each line of the dump.
* @param p Pointer to the memory region to dump.
* @param len Length of the memory region in bytes.
**/
void wpr_acl_hexdump(const char *tag, const void *p, size_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    char line[128];
    size_t offset = 0;

    while (offset < len) {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "%s +0x%02zx: ", tag, offset);
        for (size_t i = 0; i < 16 && offset + i < len; i++) {
            pos += snprintf(line + pos, sizeof(line) - pos,
                            "%02x%s", b[offset + i],
                            (i == 7) ? "  " : " ");
        }
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "%s\n", line);
        offset += 16;
    }
}

/** 
* Print an IPv4 ACL rule configuration to the log for debugging.
* @param r Pointer to the IPv4 ACL rule configuration to print.
**/
void wpr_acl_print_ip4_rule(const wpr_acl_ip4_rule_cfg_t *r)
{
    if (!r)
        return;

    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];
    struct in_addr ina;

    //print raw ip addresses 
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "Raw IPs: src=0x%08x dst=0x%08x\n", r->src_ip, r->dst_ip);
    ina.s_addr = htonl(r->src_ip);
    inet_ntop(AF_INET, &ina, src_buf, sizeof(src_buf));
    
    ina.s_addr = htonl(r->dst_ip);
    inet_ntop(AF_INET, &ina, dst_buf, sizeof(dst_buf));

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "ACL IPv4 rule: id=%u tenant=%u/%u priority=%d\n",
            r->rule_id, r->tenant_id_lo, r->tenant_id_hi, r->priority);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    match: %s/%u:%u-%u -> %s/%u:%u-%u proto=%s(%u)\n",
            src_buf, r->src_prefix,
            r->src_port_lo,
            r->src_port_hi,
            dst_buf, r->dst_prefix,
            r->dst_port_lo,
            r->dst_port_hi,
            wpr_proto_to_str(r->proto), r->proto);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    ingress_ports: %u-%u\n",
            r->in_port_lo, r->in_port_hi);

    wpr_acl_print_action(&r->action);
}

/** 
* Print an IPv6 ACL rule configuration to the log for debugging.
* @param r Pointer to the IPv6 ACL rule configuration to print. 
**/
void wpr_acl_print_ip6_rule(const wpr_acl_ip6_rule_cfg_t *r)
{
    if (!r)
        return;

    char src_buf[INET6_ADDRSTRLEN];
    char dst_buf[INET6_ADDRSTRLEN];
    struct in6_addr in6;

    memcpy(&in6, r->src_ip, sizeof(in6));
    inet_ntop(AF_INET6, &in6, src_buf, sizeof(src_buf));

    memcpy(&in6, r->dst_ip, sizeof(in6));
    inet_ntop(AF_INET6, &in6, dst_buf, sizeof(dst_buf));

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "ACL IPv6 rule: id=%u tenant=%u/%u priority=%d\n",
            r->rule_id, r->tenant_id_lo, r->tenant_id_hi, r->priority);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    match: %s/%u:%u-%u -> %s/%u:%u-%u proto=%s(%u)\n",
            src_buf, r->src_prefix,
            r->src_port_lo,
            r->src_port_hi,
            dst_buf, r->dst_prefix,
            r->dst_port_lo,
            r->dst_port_hi,
            wpr_proto_to_str(r->proto), r->proto);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    ingress_ports: %u-%u\n",
            r->in_port_lo, r->in_port_hi);

    wpr_acl_print_action(&r->action);
}


/** 
* Print an L2 ACL rule configuration to the log for debugging.
* @param r Pointer to the L2 ACL rule configuration to print.
**/
void wpr_acl_print_l2_rule(const wpr_acl_l2_rule_cfg_t *r)
{
    if (!r)
        return;

    char src_mac[32];
    char dst_mac[32];

    wpr_format_mac(&r->src_mac, src_mac, sizeof(src_mac));
    wpr_format_mac(&r->dst_mac, dst_mac, sizeof(dst_mac));

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "ACL L2 rule: id=%u tenant=%u/%u priority=%d\n",
            r->rule_id, r->tenant_id_lo, r->tenant_id_hi, r->priority);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    ingress_ports: %u-%u\n",
            r->in_port_lo, r->in_port_hi);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    VLANs: outer=%u-%u inner=%u-%u\n",
            r->outer_vlan_lo, r->outer_vlan_hi,
            r->inner_vlan_lo, r->inner_vlan_hi);

    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "    ether_type: 0x%04x (%s)\n",
            r->ether_type, wpr_ethertype_to_str(r->ether_type));

    if (r->is_mac_match) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                "    MAC match: src=%s dst=%s\n",
                src_mac, dst_mac);
    } else {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                "    MAC match: disabled\n");
    }

    wpr_acl_print_action(&r->action);
}


/*-------------------------------------------- WPR_ACL Helper Functions ----------------------------------------------*/

/** 
* Apply an IPv6 prefix length to the ACL fields for masking.
* This function sets the mask_range.u32 values in the provided fields array
* according to the specified prefix length.
* @param fields Array of 4 rte_acl_field structures representing the IPv6 address fields.
* @param prefix_len The IPv6 prefix length (0-128). 
**/
static inline void
apply_ipv6_prefix(struct rte_acl_field fields[4], uint8_t prefix_len)
{
    const uint32_t full_mask = 0xFFFFFFFFu;

    /* /0 -> wildcard: all mask_range = 0 */
    if (prefix_len == 0) {
        for (int i = 0; i < 4; i++)
            fields[i].mask_range.u32 = 0;
        return;
    }

    /* Clamp anything >128 just to be defensive */
    if (prefix_len > 128)
        prefix_len = 128;

    int idx = 0;

    /* Full 32-bit chunks first */
    while (prefix_len >= 32 && idx < 4) {
        fields[idx].mask_range.u32 = full_mask;
        prefix_len -= 32;
        idx++;
    }

    /* Partial chunk, if any bits remain and we still have a field */
    if (prefix_len > 0 && idx < 4) {
        uint32_t mask = ~((1u << (32 - prefix_len)) - 1u);
        fields[idx].mask_range.u32 = mask;
        idx++;
    }

    /* Any remaining fields after the prefix are wildcard */
    while (idx < 4) {
        fields[idx].mask_range.u32 = 0;
        idx++;
    }
}

static inline uint32_t mask_from_prefix(uint8_t prefix)
{
    if (prefix == 0)
        return 0u;              /* wildcard */
    if (prefix >= 32)
        return 0xFFFFFFFFu;     /* /32 exact */
    return ~((1u << (32 - prefix)) - 1u);
}


/** 
* Fill the ACL fields for an IPv6 address stored in network byte order. 
* handles converting each chunk into host byte order and populating the fields array.
* @param be_addr The IPv6 address in network byte order (16 bytes).
* @param fields Array of 4 rte_acl_field structures to fill with the address chunks.    
**/
static void acl_ipv6_rule_fill(const uint8_t be_addr[16],
                                      struct rte_acl_field fields[4])
{
    const uint32_t *p = (const uint32_t *)be_addr;

    uint32_t v0 = rte_be_to_cpu_32(p[0]);
    uint32_t v1 = rte_be_to_cpu_32(p[1]);
    uint32_t v2 = rte_be_to_cpu_32(p[2]);
    uint32_t v3 = rte_be_to_cpu_32(p[3]);

    // Example: each field is a /32 chunk of the 128-bit address
    fields[0].value.u32 = v0;
    fields[1].value.u32 = v1;
    fields[2].value.u32 = v2;
    fields[3].value.u32 = v3;

    // You’ll also set mask_range.u32 and category/field_idx/etc here
}

/**
* Callback function to free retired action entries. DO NOT call this directly, registered with RCU DQ at init. 
*
* @param arg
*   Optional context argument (unused here).
* @param entries
*   Array of pointers to entries to free.
* @param n
*   Number of entries in the array. 
**/
static void wpr_acl_ctx_rcu_free(void *arg, void *entries, unsigned int n)
{
    (void)arg; // optional context, ignore if unused
    void **arr = (void **)entries;   // array of pointers, n elements
    for (unsigned int i = 0; i < n; i++) {
        if(!arr[i])
            continue;

        rte_acl_free(arr[i]);
    }
}

/** 
* Callback function to free retired ACL policy tables. DO NOT call this directly, registered with RCU DQ at init. 
* @param arg
*   Optional context argument (unused here).
* @param entries
*   Array of pointers to entries to free.
* @param n
*   Number of entries in the array.
**/
static void wpr_acl_tables_rcu_free(void *arg, void *entries, unsigned int n)
{
    (void)arg;
    void **arr = (void **)entries;

    for (unsigned int i = 0; i < n; i++) {
        if (!arr[i])
            continue;
        rte_free(arr[i]);   // tables are allocated with rte_zmalloc_socket
    }
}


/** 
* Callback function to free retired ACL global stats structures. DO NOT call this directly, registered with RCU DQ at init. 
* @param arg
*   Optional context argument (unused here).
* @param entries
*   Array of pointers to entries to free.
* @param n
*   Number of entries in the array.
**/
static void wpr_acl_stats_rcu_free(void *arg, void *entries, unsigned int n)
{
    (void)arg;
    void **arr = (void **)entries;

    for (unsigned int i = 0; i < n; i++) {
        if (!arr[i])
            continue;
        rte_free(arr[i]);   // tables are allocated with rte_zmalloc_socket
    }
}

/** 
* ACL Context retire function - we don't delete immediately, but enqueue for deferred freeing by QSBR mechanism. Called when swapping in new ACL contexts.
* @param rt
*   Pointer to ACL runtime structure
* @param old_ctx
*   Pointer to old ACL context to retire
* @return
*   0 on success, negative errno on failure.
**/
static int wpr_acl_retire_ctx(wpr_acl_runtime_t *rt, struct rte_acl_ctx *old_ctx)
{
    if (!rt || !old_ctx)
        return -EINVAL;

    int ret = rte_rcu_qsbr_dq_enqueue(rt->acl_ctx_qsbr_dq, &old_ctx);
    if (ret != 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "Failed to enqueue old ACL context for deferred free: %s\n",
                rte_strerror(-ret));
        return ret;
    }

    return 0;
}

/** 
* ACL Policy Tables retire function - we don't delete immediately, but enqueue for deferred freeing. Called when swapping in new tables.
* @param rt
*   Pointer to ACL runtime structure
* @param old_tbl
*   Pointer to old ACL policy tables to retire
* @return
*   0 on success, negative errno on failure.
**/
static int wpr_acl_retire_table(wpr_acl_runtime_t *rt, wpr_acl_policy_tables_t *old_tbl)
{
    if (!rt || !old_tbl)
        return -EINVAL;

    int ret = rte_rcu_qsbr_dq_enqueue(rt->acl_tables_qsbr_dq, &old_tbl);
    if (ret != 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "Failed to enqueue old ACL tables for deferred free: %s\n",
                rte_strerror(-ret));
        return ret;
    }

    return 0;
}


/** 
* ACL Global Stats retire function - we don't delete immediately, but enqueue for deferred freeing. Called when swapping in new stats.
* @param rt
*   Pointer to ACL runtime structure
* @param old_stats
*   Pointer to old ACL global stats to retire
* @return
*   0 on success, negative errno on failure.    
**/
static int wpr_acl_retire_global_stats(wpr_acl_runtime_t *rt, wpr_acl_rule_db_stats_t *old_stats)
{
    if (!rt || !old_stats)
        return -EINVAL;

    int ret = rte_rcu_qsbr_dq_enqueue(rt->acl_stats_qsbr_dq, &old_stats);
    if (ret != 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "Failed to enqueue old ACL tables for deferred free: %s\n",
                rte_strerror(-ret));
        return ret;
    }

    return 0;
}

/** 
* Perform QSBR reclamation for retired load balancer nodes.
* @param mgr
*   Pointer to load balancing manager structure. 
**/
void wpr_acl_qsbr_reclaim(wpr_acl_runtime_t *rt)
{
    unsigned int freed = 0, pending= 0, avail = 0;
    rte_rcu_qsbr_dq_reclaim(rt->acl_ctx_qsbr_dq, rt->qsbr_max_reclaim_size, &freed, &pending, &avail);
    if (freed > 0) {
        WPR_LOG(WPR_LOG_LB, RTE_LOG_DEBUG, "Reclaimed %u retired LB nodes, %u still pending, %u slots available\n", freed, pending, avail);
    }

    freed = 0;
    pending= 0;
    avail = 0;
    rte_rcu_qsbr_dq_reclaim(rt->acl_tables_qsbr_dq, rt->qsbr_max_reclaim_size, &freed, &pending, &avail);
    if (freed > 0) {
        WPR_LOG(WPR_LOG_LB, RTE_LOG_DEBUG, "Reclaimed %u retired LB groups, %u still pending, %u slots available\n", freed, pending, avail);
    }
}

/** 
* Initialize the ACL runtime structure. Call this in main thread before using any other ACL API functions.
* @param rt
*   Pointer to ACL runtime structure to initialize.
= @param socket_id
*   NUMA socket ID for memory allocation.
* @param rcu_ctx
*   Pointer to RCU context for QSBR support.
* @param ge
*   Pointer to global epoch tracker struct.
* @param reclaim_trigger
*   Number of deferred objects in the queue to trigger reclamation.
* @param max_reclaim
*   Maximum number of deferred objects to reclaim in one call.
* @return
*   0 on success, negative errno on failure.    
**/
int  wpr_acl_runtime_init(wpr_acl_runtime_t *rt, int socket_id, wpr_rcu_ctx_t *rcu_ctx, wpr_global_policy_epoch_t *ge, 
    uint32_t reclaim_trigger,uint32_t max_reclaim, unsigned int num_workers)
{
    //guard on NULL 
    if (!rt)
        return -EINVAL;

    //clear runtime context pointer
    memset(rt, 0, sizeof(*rt));
    rt->socket_id = socket_id;
    rt->lifetime_build_id = 0;
    rt->worker_cores = num_workers;

    //assign global epoch tracker pointer
    rt->epoch_ctx = ge;

    //initialize runtime struct pointers
    atomic_store(&rt->ip4_acl_curr, NULL);
    atomic_store(&rt->ip6_acl_curr, NULL);
    atomic_store(&rt->l2_acl_curr,  NULL);

    atomic_store(&rt->policy_tables_curr, NULL);

    //capture qsbr context pointer
    rt->qsbr_ctx = rcu_ctx;

    //allocate per worker ACL stats, these live for the lifetime of the runtime
    //we don't allocate global stats here though, they get swapped in at build / commit time. 
    rt->stats_shards = rte_zmalloc_socket("wpr_acl_stats_shards",
                                        sizeof(wpr_acl_stats_shard_t) * RTE_MAX_LCORE,
                                        RTE_CACHE_LINE_SIZE,
                                        socket_id);
    if (!rt->stats_shards) {
        memset(rt, 0, sizeof(*rt));
        return -ENOMEM;
    }

    // Initialize QSBR DQ structure for ACL context reclamation
    struct rte_rcu_qsbr_dq_parameters group_params = {
        .name                  = "wpr_acl_ctx_dq",
        .v                     = rt->qsbr_ctx->qs,
        .size                  = 1024,
        .esize                 = sizeof(void *),
        .free_fn               = wpr_acl_ctx_rcu_free,
        .trigger_reclaim_limit = reclaim_trigger,
        .max_reclaim_size      = max_reclaim,
    };
    rt->acl_ctx_qsbr_dq = rte_rcu_qsbr_dq_create(&group_params);
    if (!rt->acl_ctx_qsbr_dq) {
        return -ENOMEM;
    }

    //initialise QSBR DQ structure for ACL policy tables reclamation
    struct rte_rcu_qsbr_dq_parameters tables_params = {
        .name                  = "wpr_acl_tables_dq",
        .v                     = rt->qsbr_ctx->qs,
        .size                  = 1024,
        .esize                 = sizeof(void *),
        .free_fn               = wpr_acl_tables_rcu_free,
        .trigger_reclaim_limit = reclaim_trigger,
        .max_reclaim_size      = max_reclaim,
    };
    rt->acl_tables_qsbr_dq = rte_rcu_qsbr_dq_create(&tables_params);
    if (!rt->acl_tables_qsbr_dq) {
        rte_rcu_qsbr_dq_delete(rt->acl_ctx_qsbr_dq);
        memset(rt, 0, sizeof(*rt));
        return -ENOMEM;
    }

    //initialise QSBR DQ structure for ACL global_stats reclamation
    struct rte_rcu_qsbr_dq_parameters stats_params = {
        .name                  = "wpr_acl_stats_dq",
        .v                     = rt->qsbr_ctx->qs,
        .size                  = 1024,
        .esize                 = sizeof(void *),
        .free_fn               = wpr_acl_stats_rcu_free,
        .trigger_reclaim_limit = reclaim_trigger,
        .max_reclaim_size      = max_reclaim,
    };
    rt->acl_stats_qsbr_dq = rte_rcu_qsbr_dq_create(&stats_params);
    if (!rt->acl_stats_qsbr_dq) {
        rte_rcu_qsbr_dq_delete(rt->acl_ctx_qsbr_dq);
        rte_rcu_qsbr_dq_delete(rt->acl_tables_qsbr_dq);
        memset(rt, 0, sizeof(*rt));
        return -ENOMEM;
    }

    rt->qsbr_max_reclaim_size = max_reclaim;
    return 0;
}

/** 
* Tear down a ACL runtime structure. Processes all outstanding deferred retires and frees all resources allocated by the API. 
* @param rt
*   Pointer to ACL runtime structure to deinitialize.
**/
void wpr_acl_runtime_deinit(wpr_acl_runtime_t *rt)
{
    if (!rt)
        return;

    struct rte_acl_ctx *ctx;
    ctx = atomic_load(&rt->ip4_acl_curr);
    if (ctx)
        rte_acl_free(ctx);

    ctx = atomic_load(&rt->ip6_acl_curr);
    if (ctx)
        rte_acl_free(ctx);

    ctx = atomic_load(&rt->l2_acl_curr);
    if (ctx)
        rte_acl_free(ctx);

    //free worker stats shards
    if (rt->stats_shards)
        rte_free(rt->stats_shards);

    // policy tables: free current immediately (we're shutting down)
    wpr_acl_policy_tables_t *tables = atomic_load(&rt->policy_tables_curr);
    if (tables)
        rte_free(tables);

    wpr_acl_rule_db_stats_t *global_stats = atomic_load(&rt->global_stats_curr);
    if (global_stats)
        rte_free(global_stats);

    // QSBR: synchronize and drain both queues
    rte_rcu_qsbr_synchronize(rt->qsbr_ctx->qs, RTE_QSBR_THRID_INVALID);

    if (rt->acl_ctx_qsbr_dq) {
        unsigned int freed, pending, avail;
        do {
            freed = pending = avail = 0;
            rte_rcu_qsbr_dq_reclaim(rt->acl_ctx_qsbr_dq, 1,
                                    &freed, &pending, &avail);
        } while (pending);
        rte_rcu_qsbr_dq_delete(rt->acl_ctx_qsbr_dq);
    }

    if (rt->acl_tables_qsbr_dq) {
        unsigned int freed, pending, avail;
        do {
            freed = pending = avail = 0;
            rte_rcu_qsbr_dq_reclaim(rt->acl_tables_qsbr_dq, 1,
                                    &freed, &pending, &avail);
        } while (pending);
        rte_rcu_qsbr_dq_delete(rt->acl_tables_qsbr_dq);
    }

    if(rt->acl_stats_qsbr_dq) {
        unsigned int freed, pending, avail;
        do {
            freed = pending = avail = 0;
            rte_rcu_qsbr_dq_reclaim(rt->acl_stats_qsbr_dq, 1,
                                    &freed, &pending, &avail);
        } while (pending);
        rte_rcu_qsbr_dq_delete(rt->acl_stats_qsbr_dq);
    }

    memset(rt, 0, sizeof(*rt));
}


/** 
* Create a new DPDK RTE ACL Context given parameters passed in by the user. builds a parameter struct, initialzes the context, returns. 
* @param name
*   Name of the ACL context.
* @param socket_id
*   NUMA socket ID for memory allocation.
* @param max_rules
*   Maximum number of rules the context will hold.
* @param rule_size
*   Size of each rule in bytes.
* @return
*   Pointer to newly created ACL context, or NULL on failure.
**/
static struct rte_acl_ctx *wpr_acl_create_ctx(const char *name, int socket_id, uint32_t max_rules, uint32_t rule_size)
{
    struct rte_acl_param param = {
        .name        = name,
        .socket_id   = socket_id,
        .rule_size   = rule_size,
        .max_rule_num = max_rules,
    };
    return rte_acl_create(&param);
}


/** 
* Begin building a new ACL policy. Initializes build context structures for both IP4 and L2 ACLs.
* @param bld
*   Pointer to ACL build context to initialize.
* @param rt
*   Pointer to ACL runtime structure.
* @param max_ip4_rules
*   Maximum number of IPv4 rules to allocate space for.
* @param max_l2_rules
*   Maximum number of L2 rules to allocate space for.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_build_begin(wpr_acl_build_ctx_t *bld, const wpr_acl_runtime_t *rt, uint32_t max_ip4_rules, uint32_t max_ip6_rules, uint32_t max_l2_rules)
{
    //Guard on null pointers 
    if (!bld || !rt)
        return -EINVAL;


    memset(bld, 0, sizeof(*bld));
    bld->socket_id = rt->socket_id;

    bld->tables_build = rte_zmalloc_socket("wpr_acl_tables_build",
                                           sizeof(*bld->tables_build),
                                           RTE_CACHE_LINE_SIZE,
                                           bld->socket_id);
    if (!bld->tables_build)
        goto error;

    bld->global_stats_build = rte_zmalloc_socket("wpr_acl_global_stats_build",
                                           sizeof(wpr_acl_rule_db_stats_t),
                                           RTE_CACHE_LINE_SIZE,
                                           bld->socket_id);
    if (!bld->global_stats_build)
        goto error;

    //currently we are not extending rule size, so use default size
    uint32_t ip_rule_size = RTE_ACL_RULE_SZ(WPR_ACL_IP4_NUM_FIELDS);
    uint32_t ip6_rule_size = RTE_ACL_RULE_SZ(WPR_ACL_IP6_NUM_FIELDS);
    uint32_t l2_rule_size = RTE_ACL_RULE_SZ(WPR_ACL_L2_NUM_FIELDS);

    char acl_name[RTE_ACL_NAMESIZE];
    snprintf(acl_name, sizeof(acl_name), "wpr_ip4_acl_%u", rt->lifetime_build_id);

    bld->ip4_acl_build = max_ip4_rules ? wpr_acl_create_ctx(acl_name, bld->socket_id, max_ip4_rules, ip_rule_size) : NULL;
    if(!bld->ip4_acl_build && max_ip4_rules)
        goto error;

    snprintf(acl_name, sizeof(acl_name), "wpr_ip6_acl_%u", rt->lifetime_build_id);
    bld->ip6_acl_build = max_ip6_rules ? wpr_acl_create_ctx(acl_name, bld->socket_id, max_ip6_rules, ip6_rule_size) : NULL;
    if(!bld->ip6_acl_build && max_ip6_rules)
        goto error;

    snprintf(acl_name, sizeof(acl_name), "wpr_l2_acl_%u", rt->lifetime_build_id);
    bld->l2_acl_build = max_l2_rules ? wpr_acl_create_ctx(acl_name, bld->socket_id, max_l2_rules, l2_rule_size) : NULL;
    if(!bld->l2_acl_build && max_l2_rules)
        goto error;

    return 0;

error:
    wpr_acl_build_abort(bld);
    return -ENOMEM;
}

/** 
* Free any partially built ACL policy and release build context resources.
* @param bld
*   Pointer to ACL build context to abort.
**/
void wpr_acl_build_abort(wpr_acl_build_ctx_t *bld)
{
    if (!bld)
        return;

    if (bld->ip4_acl_build) {
        rte_acl_free(bld->ip4_acl_build);
        bld->ip4_acl_build = NULL;
    }
    if (bld->l2_acl_build) {
        rte_acl_free(bld->l2_acl_build);
        bld->l2_acl_build = NULL;
    }
    if (bld->ip6_acl_build) {
        rte_acl_free(bld->ip6_acl_build);
        bld->ip6_acl_build = NULL;
    }
    if (bld->tables_build) {
        rte_free(bld->tables_build);
        bld->tables_build = NULL;
    }

    if (bld->global_stats_build) {
        rte_free(bld->global_stats_build);
        bld->global_stats_build = NULL;
    }

    memset(bld, 0, sizeof(*bld));
}


/** 
* Internal function to add an IPv4 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param ctx
*   Pointer to the DPDK RTE ACL context to add the rule to.
* @param bld
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the IPv4 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
static int wpr_acl_add_ip4_rule_internal(struct rte_acl_ctx *ctx,
                              wpr_acl_build_ctx_t *bld,
                              const wpr_acl_ip4_rule_cfg_t *rcfg)
{
    //guard on null pointers
    if (! ctx || !bld || ! rcfg)
        return -EINVAL;

    //guard on rule_id range
    if (rcfg->rule_id >= WPR_ACL_MAX_RULES)
        return -EINVAL;

    //allocate rule structure
    size_t rule_sz = RTE_ACL_RULE_SZ(WPR_ACL_IP4_NUM_FIELDS);
    struct rte_acl_rule *r = rte_zmalloc("acl_rule", rule_sz, 0);
    if (! r)
        return -ENOMEM;

    // ALL fields in HOST byte order for consistent matching. API assumes host order inputs in cfg strcuts!!! 
    
    // Tenant exact via range [id,id]
    r->field[WPR_ACL_IP4_FIELD_TENANT].value. u32      = rcfg->tenant_id_lo;
    r->field[WPR_ACL_IP4_FIELD_TENANT].mask_range.u32 = rcfg->tenant_id_hi;

    // Ingress port range [lo, hi]
    r->field[WPR_ACL_IP4_FIELD_IN_PORT].value. u32      = rcfg->in_port_lo;
    r->field[WPR_ACL_IP4_FIELD_IN_PORT].mask_range.u32 = rcfg->in_port_hi;

    // Src/dst IP
    r->field[WPR_ACL_IP4_FIELD_SRC_IP].value.u32      = rcfg->src_ip;
    r->field[WPR_ACL_IP4_FIELD_SRC_IP]. mask_range.u32 = rcfg->src_prefix;

    r->field[WPR_ACL_IP4_FIELD_DST_IP]. value.u32      = rcfg->dst_ip;
    r->field[WPR_ACL_IP4_FIELD_DST_IP].mask_range.u32 = rcfg->dst_prefix;

    // Ports
    r->field[WPR_ACL_IP4_FIELD_SRC_PORT].value.u32      = rcfg->src_port_lo;
    r->field[WPR_ACL_IP4_FIELD_SRC_PORT]. mask_range.u32 = rcfg->src_port_hi;

    r->field[WPR_ACL_IP4_FIELD_DST_PORT].value. u32      = rcfg->dst_port_lo;
    r->field[WPR_ACL_IP4_FIELD_DST_PORT].mask_range.u32 = rcfg->dst_port_hi;

    // Proto: single byte
    if (rcfg->proto == 0) {
        r->field[WPR_ACL_IP4_FIELD_PROTO].value.u8      = 0;
        r->field[WPR_ACL_IP4_FIELD_PROTO].mask_range.u8 = 0;
    } else {
        r->field[WPR_ACL_IP4_FIELD_PROTO]. value.u8      = rcfg->proto;
        r->field[WPR_ACL_IP4_FIELD_PROTO].mask_range.u8 = 0xff;
    }

    // Meta rule properties
    // - single category for all rules
    // - priority from cfg
    // - userdata = rule_id + 1 (0 = miss)
    r->data.category_mask = 1u;
    r->data.priority      = rcfg->priority;
    r->data.userdata      = rcfg->rule_id + 1;   // 0 = miss


    wpr_acl_debug_dump_ip4_rule(r);

    //add the rule to the context and check for errors
    //regardless of outcome we are done with the rule structure so make sure to free it
    int rc = rte_acl_add_rules(ctx, r, 1);
    rte_free(r);
    if (rc < 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "rte_acl_add_rules failed rc=%d (errno=%d)\n", rc, rte_errno);
        return rc;
    }

    // Stash action in build tables
    bld->tables_build->ip4_actions[rcfg->rule_id] = rcfg->action;
    bld->tables_build->ip4_actions[rcfg->rule_id].hit = true;
    bld->tables_build->ip4_actions[rcfg->rule_id].idx = rcfg->rule_id;
    bld->tables_build->ip4_actions[rcfg->rule_id].priority = rcfg->priority;

    return 0;
}

/** 
* Public function to add an IPv4 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param bld
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the IPv4 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_build_add_ip4_rule(wpr_acl_build_ctx_t *bld,
                           const wpr_acl_ip4_rule_cfg_t *rcfg)
{
    if (!bld || !bld->ip4_acl_build || !rcfg)
        return -EINVAL;

    int rc = wpr_acl_add_ip4_rule_internal(bld->ip4_acl_build, bld, rcfg);
    if (rc == 0)
        bld->ip4_rule_count++;
    return rc;
}

/** 
* Internal function to add an IPv6 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param ctx
*   Pointer to the DPDK RTE ACL context to add the rule to.
* @param bld
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the IPv6 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
static int wpr_acl_add_ip6_rule_internal(struct rte_acl_ctx *ctx,
                              wpr_acl_build_ctx_t *bld,
                              const wpr_acl_ip6_rule_cfg_t *rcfg)
{   

    //guard on null pointers
    if (!ctx || !bld || !rcfg)
        return -EINVAL;

    //guard on rule_id range
    if (rcfg->rule_id >= WPR_ACL_MAX_RULES)
        return -EINVAL;

    //allocate rule structure
    size_t rule_sz = sizeof(struct rte_acl_rule) + sizeof(struct rte_acl_field) * WPR_ACL_IP6_NUM_FIELDS;
    struct rte_acl_rule *r = rte_zmalloc("acl_rule", rule_sz, 0);
    if (!r) 
        return -ENOMEM;

    // All fields in HOST byte order for consistent matching. API assumes host order inputs in cfg strcuts!!!

    //tenant exact [id,id]
    r->field[WPR_ACL_IP6_FIELD_TENANT].value.u32      = rcfg->tenant_id_lo;
    r->field[WPR_ACL_IP6_FIELD_TENANT].mask_range.u32 = rcfg->tenant_id_hi;

    // Ingress port [lo,hi]
    r->field[WPR_ACL_IP6_FIELD_IN_PORT].value.u32      = rcfg->in_port_lo;
    r->field[WPR_ACL_IP6_FIELD_IN_PORT].mask_range.u32 = rcfg->in_port_hi;

    // IPv6 addresses: convert 16-byte array into 4x u32 and split prefix
    uint32_t src32[4], dst32[4];
    memcpy(src32, rcfg->src_ip, 16);
    memcpy(dst32, rcfg->dst_ip, 16);

    // The first 4 fields = 128-bit IPv6 src address
    acl_ipv6_rule_fill(rcfg->src_ip, &r->field[WPR_ACL_IP6_FIELD_SRC_IP0]);
    apply_ipv6_prefix(&r->field[WPR_ACL_IP6_FIELD_SRC_IP0], rcfg->src_prefix);

    // Next 4 fields = 128-bit IPv6 dst address
    acl_ipv6_rule_fill(rcfg->dst_ip, &r->field[WPR_ACL_IP6_FIELD_DST_IP0]);
    apply_ipv6_prefix(&r->field[WPR_ACL_IP6_FIELD_DST_IP0], rcfg->dst_prefix);

    // Ports
    r->field[WPR_ACL_IP6_FIELD_SRC_PORT].value.u16      = rcfg->src_port_lo;
    r->field[WPR_ACL_IP6_FIELD_SRC_PORT].mask_range.u16 = rcfg->src_port_hi;

    r->field[WPR_ACL_IP6_FIELD_DST_PORT].value.u16      = rcfg->dst_port_lo;
    r->field[WPR_ACL_IP6_FIELD_DST_PORT].mask_range.u16 = rcfg->dst_port_hi;

    // Proto
    if (rcfg->proto == 0) {
        r->field[WPR_ACL_IP6_FIELD_PROTO].value.u8      = 0;
        r->field[WPR_ACL_IP6_FIELD_PROTO].mask_range.u8 = 0;      /* wildcard */
    } else {
        r->field[WPR_ACL_IP6_FIELD_PROTO].value.u8      = rcfg->proto;
        r->field[WPR_ACL_IP6_FIELD_PROTO].mask_range.u8 = 0xff;   // exact
    }

    // Meta rule properties
    // - single category for all rules
    // - priority from cfg
    // - userdata = rule_id + 1 (0 = miss)
    r->data.category_mask = 1u;
    r->data.priority      = rcfg->priority;
    r->data.userdata      = rcfg->rule_id + 1;

    //add the rule to the context and check for errors. 
    //regardless of outcome we are done with the rule structure so make sure to free it
    wpr_acl_debug_dump_ip6_rule(r);
    int rc = rte_acl_add_rules(ctx, r, 1);
    rte_free(r);
    if (rc < 0)
        return rc;

    // Stash action in build tables
    bld->tables_build->ip6_actions[rcfg->rule_id] = rcfg->action;
    bld->tables_build->ip6_actions[rcfg->rule_id].hit = true;
    bld->tables_build->ip6_actions[rcfg->rule_id].idx = rcfg->rule_id;
    bld->tables_build->ip6_actions[rcfg->rule_id].priority = rcfg->priority;

    return 0;
}


/** 
* Public function to add an IPv6 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param bld    
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the IPv6 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_build_add_ip6_rule(wpr_acl_build_ctx_t *bld,
                               const wpr_acl_ip6_rule_cfg_t *rcfg)
{
    if (!bld || !bld->ip6_acl_build || !rcfg)
        return -EINVAL;

    int rc = wpr_acl_add_ip6_rule_internal(bld->ip6_acl_build, bld, rcfg);
    if (rc == 0)
        bld->ip6_rule_count++;
    return rc;
}


/** 
* Internal function to add an L2 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param ctx
*   Pointer to the DPDK RTE ACL context to add the rule to.
* @param bld
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the L2 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
static int wpr_acl_add_l2_rule_internal(struct rte_acl_ctx *ctx,
                             wpr_acl_build_ctx_t *bld,
                             const wpr_acl_l2_rule_cfg_t *rcfg)
{
    //guard on null pointers
    if (!ctx || !bld || !rcfg)
        return -EINVAL;

    //guard on rule_id range
    if (rcfg->rule_id >= WPR_ACL_MAX_RULES)
        return -EINVAL;

    //allocate rule structure
    size_t rule_sz = sizeof(struct rte_acl_rule) + sizeof(struct rte_acl_field) * WPR_ACL_L2_NUM_FIELDS;
    struct rte_acl_rule *r = rte_zmalloc("acl_rule", rule_sz, 0);
    if (!r) 
        return -ENOMEM;

    // Initialize rule fields in HOST byte order for consistent matching. API assumes host order inputs in cfg strcuts!!!

    // Tenant
    r->field[WPR_ACL_L2_FIELD_TENANT].value.u32      = rcfg->tenant_id_lo;
    r->field[WPR_ACL_L2_FIELD_TENANT].mask_range.u32 = rcfg->tenant_id_hi;

    // Ingress port range
    r->field[WPR_ACL_L2_FIELD_IN_PORT].value.u16      = rcfg->in_port_lo;
    r->field[WPR_ACL_L2_FIELD_IN_PORT].mask_range.u16 = rcfg->in_port_hi;

    // VLANs
    r->field[WPR_ACL_L2_FIELD_OUTER_VLAN].value.u16      = rcfg->outer_vlan_lo;
    r->field[WPR_ACL_L2_FIELD_OUTER_VLAN].mask_range.u16 = rcfg->outer_vlan_hi;

    r->field[WPR_ACL_L2_FIELD_INNER_VLAN].value.u16      = rcfg->inner_vlan_lo;
    r->field[WPR_ACL_L2_FIELD_INNER_VLAN].mask_range.u16 = rcfg->inner_vlan_hi;

    // EtherType
    if (rcfg->ether_type == 0) {
        r->field[WPR_ACL_L2_FIELD_ETHER_TYPE].value.u16      = 0;
        r->field[WPR_ACL_L2_FIELD_ETHER_TYPE].mask_range.u16 = 0;     // wildcard
    } else {
        r->field[WPR_ACL_L2_FIELD_ETHER_TYPE].value.u16      = rcfg->ether_type;
        r->field[WPR_ACL_L2_FIELD_ETHER_TYPE].mask_range.u16 = 0xffff;
    }

    // MACs: pack 6B into low 48 bits, note we include a specific check mac match enable flag
    if (rcfg->is_mac_match) {
        const uint8_t *s = rcfg->src_mac.addr_bytes;
        const uint8_t *d = rcfg->dst_mac.addr_bytes;

        uint16_t sm_hi = ((uint16_t)s[0] << 8) | s[1];
        uint32_t sm_lo = ((uint32_t)s[2] << 24) |
                        ((uint32_t)s[3] << 16) |
                        ((uint32_t)s[4] << 8)  |
                        (uint32_t)s[5];

        uint16_t dm_hi = ((uint16_t)d[0] << 8) | d[1];
        uint32_t dm_lo = ((uint32_t)d[2] << 24) |
                        ((uint32_t)d[3] << 16) |
                        ((uint32_t)d[4] << 8)  |
                        (uint32_t)d[5];

        r->field[WPR_ACL_L2_FIELD_SRC_MAC_HI].value.u16 = sm_hi;
        r->field[WPR_ACL_L2_FIELD_SRC_MAC_HI].mask_range.u16 = 0xFFFF;

        r->field[WPR_ACL_L2_FIELD_SRC_MAC_LO].value.u32 = sm_lo;
        r->field[WPR_ACL_L2_FIELD_SRC_MAC_LO].mask_range.u32 = 0xFFFFFFFF;

        r->field[WPR_ACL_L2_FIELD_DST_MAC_HI].value.u16 = dm_hi;
        r->field[WPR_ACL_L2_FIELD_DST_MAC_HI].mask_range.u16 = 0xFFFF;

        r->field[WPR_ACL_L2_FIELD_DST_MAC_LO].value.u32 = dm_lo;
        r->field[WPR_ACL_L2_FIELD_DST_MAC_LO].mask_range.u32 = 0xFFFFFFFF;
    } else {
        /* wildcard MAC */
        r->field[WPR_ACL_L2_FIELD_SRC_MAC_HI].value.u16 = 0;
        r->field[WPR_ACL_L2_FIELD_SRC_MAC_HI].mask_range.u16 = 0;

        r->field[WPR_ACL_L2_FIELD_SRC_MAC_LO].value.u32 = 0;
        r->field[WPR_ACL_L2_FIELD_SRC_MAC_LO].mask_range.u32 = 0;

        r->field[WPR_ACL_L2_FIELD_DST_MAC_HI].value.u16 = 0;
        r->field[WPR_ACL_L2_FIELD_DST_MAC_HI].mask_range.u16 = 0;

        r->field[WPR_ACL_L2_FIELD_DST_MAC_LO].value.u32 = 0;
        r->field[WPR_ACL_L2_FIELD_DST_MAC_LO].mask_range.u32 = 0;
    }

    // Meta rule properties
    // - single category for all rules
    // - priority from cfg
    // - userdata = rule_id + 1 (0 = miss)
    r->data.category_mask = 1u;
    r->data.priority      = rcfg->priority;
    r->data.userdata      = rcfg->rule_id + 1;

    wpr_acl_debug_dump_l2_rule(r);

    //add the rule to the context and check for errors.
    //regardless of outcome we are done with the rule structure so make sure to free it
    int rc = rte_acl_add_rules(ctx, r, 1);
    rte_free(r);
    if (rc < 0)
        return rc;

    // Stash action in build tables
    bld->tables_build->l2_actions[rcfg->rule_id] = rcfg->action;
    bld->tables_build->l2_actions[rcfg->rule_id].hit = true;
    bld->tables_build->l2_actions[rcfg->rule_id].idx = rcfg->rule_id;
    bld->tables_build->l2_actions[rcfg->rule_id].priority = rcfg->priority;

    return 0;
}


/** 
* Public function to add an L2 ACL rule to a build context. Encodes the rule fields into the DPDK RTE ACL rule format.
* @param bld
*   Pointer to the ACL build context.
* @param rcfg
*   Pointer to the L2 ACL rule configuration to add.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_build_add_l2_rule(wpr_acl_build_ctx_t *bld,
                              const wpr_acl_l2_rule_cfg_t *rcfg)
{
    if (!bld || !bld->l2_acl_build || !rcfg)
        return -EINVAL;

    int rc = wpr_acl_add_l2_rule_internal(bld->l2_acl_build, bld, rcfg);
    if (rc == 0)
        bld->l2_rule_count++;
    return rc;
}

/**  
* Commit the built ACL policy, swapping it into the runtime structure and retiring the old policy. Note 
* we only build each ACL context (ipv4/6/l2) if there are rules present in that context. else we don't build or change it. 
* @param rt
*   Pointer to ACL runtime structure.
* @param bld
*   Pointer to ACL build context.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_acl_build_commit(wpr_acl_runtime_t *rt, wpr_acl_build_ctx_t *bld)
{
    //guard on null pointers
    if (!rt || !bld)
        return -EINVAL;

    // Build IP4 context if we have rules
    if (bld->ip4_acl_build && bld->ip4_rule_count > 0) {
        struct rte_acl_config cfg = {
            .num_categories = 1,
            .num_fields     = WPR_ACL_IP4_NUM_FIELDS,
        };
        memcpy(cfg.defs, wpr_acl_ip4_defs, sizeof(wpr_acl_ip4_defs));

        //call the build and check for errors
        int rc = rte_acl_build(bld->ip4_acl_build, &cfg);
        if (rc < 0){
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                    "rte_acl_build failed rc=%d (errno=%d)\n", rc, rte_errno);
            return rc;
        }

    }

    // Build IP6 context if we have rules
    if (bld->ip6_acl_build && bld->ip6_rule_count > 0) {
        struct rte_acl_config cfg = {
            .num_categories = 1,
            .num_fields     = WPR_ACL_IP6_NUM_FIELDS,
        };
        memcpy(cfg.defs, wpr_acl_ip6_defs, sizeof(wpr_acl_ip6_defs));

        int rc = rte_acl_build(bld->ip6_acl_build, &cfg);
        if (rc < 0){
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                    "rte_acl_build failed rc=%d (errno=%d)\n", rc, rte_errno);
            return rc;
        }
    }

    // Build L2 context if we have rules
    if (bld->l2_acl_build && bld->l2_rule_count > 0) {
        struct rte_acl_config cfg = {
            .num_categories = 1,
            .num_fields     = WPR_ACL_L2_NUM_FIELDS,
        };
        memcpy(cfg.defs, wpr_acl_l2_defs, sizeof(wpr_acl_l2_defs));

        int rc = rte_acl_build(bld->l2_acl_build, &cfg);
        if (rc < 0){
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                    "rte_acl_build failed rc=%d (errno=%d)\n", rc, rte_errno);
            return rc;
        }
    }

    //get the current ACL epoch and increment for the new policy
    uint32_t old_epoch = atomic_load_explicit(&rt->epoch_ctx->acl_policy_epoch, memory_order_acquire);
    uint32_t new_epoch = old_epoch + 1;

    struct rte_acl_ctx *old_ip4         = NULL;
    struct rte_acl_ctx *old_ip6         = NULL;
    struct rte_acl_ctx *old_l2          = NULL;
    wpr_acl_policy_tables_t *old_tables = NULL;
    wpr_acl_rule_db_stats_t *old_stats   = NULL;

    //only swap in contexts that were built (have rules)
    if (bld->ip4_rule_count > 0){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "Swapping in new IPv4 ACL context with %u rules\n", bld->ip4_rule_count);
        old_ip4 = atomic_exchange_explicit(&rt->ip4_acl_curr, bld->ip4_acl_build, memory_order_release);
    }
    
    if (bld->ip6_rule_count > 0){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "Swapping in new IPv6 ACL context with %u rules\n", bld->ip6_rule_count);
        old_ip6 = atomic_exchange_explicit(&rt->ip6_acl_curr, bld->ip6_acl_build, memory_order_release);
    }

    if (bld->l2_rule_count > 0){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "Swapping in new L2 ACL context with %u rules\n", bld->l2_rule_count);
        old_l2 = atomic_exchange_explicit(&rt->l2_acl_curr, bld->l2_acl_build, memory_order_release);
    }

    // always swap in new policy tables
    old_tables = atomic_exchange_explicit(&rt->policy_tables_curr,bld->tables_build, memory_order_release);

    //always swap in a new global stats struct 
    old_stats  = atomic_exchange_explicit(&rt->global_stats_curr,bld->global_stats_build, memory_order_release);

    // Update epoch to publish new policy
    atomic_store_explicit(&rt->epoch_ctx->acl_policy_epoch,new_epoch,memory_order_release);

    // Retire old ACL contexts and table pointers (if any)
    if (old_ip4)
        wpr_acl_retire_ctx(rt, old_ip4);
    if (old_ip6)                                    
        wpr_acl_retire_ctx(rt, old_ip6);
    if (old_l2)
        wpr_acl_retire_ctx(rt, old_l2);
    if (old_tables)
        wpr_acl_retire_table(rt, old_tables);
    if (old_stats)
        wpr_acl_retire_global_stats(rt, old_stats);
    
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "Committed new ACL policy (epoch %u)\n", new_epoch);
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "  IPv4 rules: %u\n", bld->ip4_rule_count);
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "  IPv6 rules: %u\n", bld->ip6_rule_count);
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "  L2 rules:   %u\n", bld->l2_rule_count);

    // Detach build ctx ownership
    // memset should be safe here since we have already swapped out all pointers
    bld->ip4_acl_build = NULL;
    bld->ip6_acl_build = NULL;  
    bld->l2_acl_build  = NULL;
    bld->tables_build  = NULL;
    bld->global_stats_build = NULL;
    memset(bld, 0, sizeof(*bld));

    //update lifetime build id 
    rt->lifetime_build_id++;

    return 0;
}


/** 
* RTE ACL API needs "flat" key structs; build those from WPR key IPv4 structs. Note WPR uses host byte order in flow key structs, so we convert
* them to network byte order as we build the internal key struct. This is probably a bit inefficent, <TODO> revisit flow key struct design later.
* @param fk
*   Pointer to flow key structure.
* @param in_port
*   Input port number->
* @param out
*   Pointer to output internal ACL IP4 key structure.   
**/
static inline void wpr_acl_build_ip4_key_internal(const wpr_flow_key_t *fk,
                                                  uint16_t in_port,
                                                  wpr_acl_ip4_key_internal_t *out)
{
    const wpr_flow_key_v4_t *v4 = &fk->ip.v4;
    
    memset(out, 0, sizeof(*out));

    // ALL fields in the key must be in NETWORK byte order for DPDK ACL
    out->tenant_id = rte_cpu_to_be_32(fk->tenant_id);
    out->in_port   = rte_cpu_to_be_32(in_port);

    // MASK fields: network byte order
    out->src_ip    = rte_cpu_to_be_32(v4->src_ip);
    out->dst_ip    = rte_cpu_to_be_32(v4->dst_ip);

    // RANGE fields: network byte order
    out->src_port  = rte_cpu_to_be_32(v4->src_port);
    out->dst_port  = rte_cpu_to_be_32(v4->dst_port);

    out->proto     = v4->proto;  // single byte, no conversion needed
}


/** 
* RTE ACL API needs "flat" key structs; build those from WPR key IPv6 structs. Note WPR uses host byte order in flow key structs, so we convert
* them to network byte order as we build the internal key struct. This is probably a bit inefficent, <TODO> revisit flow key struct design later.
* @param fk
*   Pointer to flow key structure.
* @param in_port
*   Input port number.
* @param out
*   Pointer to output internal ACL IP6 key structure.   
**/
static inline void wpr_acl_build_ip6_key_internal(const wpr_flow_key_t *fk,
                                                  uint16_t in_port,
                                                  wpr_acl_ip6_key_internal_t *out)
{
    const wpr_flow_key_v6_t *v6 = &fk->ip.v6;

    memset(out, 0, sizeof(*out));
    out->tenant_id = rte_cpu_to_be_32(fk->tenant_id);
    out->in_port   = rte_cpu_to_be_32(in_port);

    /* Copy 16B → 4 x u32; */
    memcpy(out->src_ip, v6->src_ip, 16);
    memcpy(out->dst_ip, v6->dst_ip, 16);

    out->src_port = rte_cpu_to_be_16(v6->src_port);
    out->dst_port = rte_cpu_to_be_16(v6->dst_port);
    out->proto    = v6->proto;
}

/** 
* RTE ACL API needs "flat" key structs; build those from WPR key L2 structs. Note WPR uses host byte order in flow key structs, so we convert
* them to network byte order as we build the internal key struct. This is probably a bit inefficent, <TODO> revisit flow key struct design later.
* @param k
*   Pointer to L2 flow key structure.
* @param out
*   Pointer to output internal ACL L2 key structure.
**/
static inline void wpr_acl_build_l2_key_internal(const wpr_l2_flow_key_t *k,
                              wpr_acl_l2_key_internal_t *out)
{
    memset(out, 0, sizeof(*out));
    out->l2_tag = 0;

    /* For L2, follow the same convention as IPv4/IPv6:
     *  - rules are in HOST byte order
     *  - keys are in NETWORK byte order
     */

    //print l2 in port 
    //WPR_LOG(WPR_LOG_ACL, RTE_LOG_INFO, "L2 key in_port in acl key conversion: %u\n", k->in_port);

    /* RANGE fields: store key in network order */
    out->tenant_id  = rte_cpu_to_be_32(k->tenant_id);
    out->outer_vlan = rte_cpu_to_be_16(k->outer_vlan);
    out->inner_vlan = rte_cpu_to_be_16(k->inner_vlan);
    out->in_port    = rte_cpu_to_be_16(k->in_port);

    /* BITMASK field: ether_type, also in network order */
    out->ether_type = rte_cpu_to_be_16(k->ether_type);

    /* MACs: pack into hi/lo same as rule builder, but convert to BE */
    const uint8_t *s = k->src.addr_bytes;
    const uint8_t *d = k->dst.addr_bytes;

    uint16_t sm_hi = ((uint16_t)s[0] << 8) | s[1];
    uint32_t sm_lo = ((uint32_t)s[2] << 24) |
                     ((uint32_t)s[3] << 16) |
                     ((uint32_t)s[4] << 8)  |
                     (uint32_t)s[5];

    uint16_t dm_hi = ((uint16_t)d[0] << 8) | d[1];
    uint32_t dm_lo = ((uint32_t)d[2] << 24) |
                     ((uint32_t)d[3] << 16) |
                     ((uint32_t)d[4] << 8)  |
                     (uint32_t)d[5];

    out->src_mac_hi = rte_cpu_to_be_16(sm_hi);
    out->src_mac_lo = rte_cpu_to_be_32(sm_lo);
    out->dst_mac_hi = rte_cpu_to_be_16(dm_hi);
    out->dst_mac_lo = rte_cpu_to_be_32(dm_lo);
}

/** 
* Classify an IP flow key against the ACL policy in the runtime structure. 
* @param rt
*   Pointer to ACL runtime structure.
* @param key
*   Pointer to flow key structure.
* @param in_port
*   Input port number.
* @param res
*   Pointer to output action/result structure provided by the user. 
**/
int wpr_acl_classify_ip(const wpr_acl_runtime_t *rt,
                        const wpr_flow_key_t    *key,
                        uint16_t                 in_port,
                        wpr_policy_action_t     *res)
{
    //guard against null pointers
    if (!rt || !key || !res){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR, "wpr_acl_classify_ip: invalid null pointer\n");
        return -EINVAL;
    }

    //make sure to zero out the result struct passed in
    memset(res, 0, sizeof(*res));

    //get IPv4/6 control structures
    struct rte_acl_ctx *ip4_ctx = atomic_load_explicit(&rt->ip4_acl_curr, memory_order_acquire);
    struct rte_acl_ctx *ip6_ctx = atomic_load_explicit(&rt->ip6_acl_curr, memory_order_acquire);
    WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
            "IPv4 classify using ctx=%p, tables=%p\n",
            (void *)ip4_ctx,
            (void *)atomic_load_explicit(&rt->policy_tables_curr,
                                        memory_order_acquire));
    //IF key is IPv4
    if (key->family == AF_INET) {
        
        //if we don't have a configured IPv4 ACL context, default NOOP instruction (ACL Stage does nothing)
        if (!ip4_ctx) {
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "No IPv4 ACL context configured, default NOOP\n");
            res->hit = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        //build internal key struct
        wpr_acl_ip4_key_internal_t k_int;

        //rte ACL engine is designed to classify batches of keys; we just have one
        //so we create a array of pointers of length 1 
        const uint8_t *keys[1];
        
        //we convert the WPR flowtable key into the internal flat key struct
        wpr_acl_build_ip4_key_internal(key, in_port, &k_int);

        wpr_acl_debug_dump_ip4_key_fields(&k_int);

        //then we point the first element of the array to our internal key struct
        keys[0] = (const uint8_t *)&k_int;

        //run classification on our single key
        //categories = 1 , we are not using multiple subtable / category lookups in this design since 
        //we maintain separate ACL contexts per table type (IP4, L2)
        const uint32_t categories = 1;
        uint32_t results[1];

        //pass the keys pointer into the classify function along with our context 
        int rc = rte_acl_classify(ip4_ctx, keys, results, 1, categories);
        if (rc < 0)
            return rc;

        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG,
                "IPv4 classify: ctx=%p result[0]=%u\n",
                (void *)ip4_ctx, results[0]);

        //get the userdata (key) from lookup results
        uint32_t userdata = results[0];

        //if userdata is 0, we had a miss, so return default NOOP action
        if (userdata == 0) {
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "IPv4 classification miss\n");
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        //if non zero we have a hit, rule index is userdata - 1
        uint32_t idx = userdata - 1;

        //if index is out of bounds, return default NOOP action
        if (idx >= WPR_ACL_MAX_RULES) {
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR, "IPv4 classification index out of bounds: %u\n", idx);
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        //if we have a valid rule entry, load the current policy tables pointer
        wpr_acl_policy_tables_t *tables = atomic_load_explicit(&rt->policy_tables_curr, memory_order_acquire);

        //if no policy tables, return default NOOP action
        if (!tables) {
            WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR, "No policy tables found during IPv4 classification\n");
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        //if we made it here, we have a valid index and policy tables, so load the action from the table
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "IPv4 classification hit index: %u\n", idx);
        *res = tables->ip4_actions[idx];

        // sanity guard
        if (!res->hit) {
            res->default_policy = FLOW_ACT_NOOP;
        }

        return 0;

    //else if we are IPv6 
    } else if (key->family == AF_INET6) {

        if (!ip6_ctx) {
            res->hit = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        wpr_acl_ip6_key_internal_t k_int;
        const uint8_t *keys[1];
        uint32_t results[1];

        wpr_acl_build_ip6_key_internal(key, in_port, &k_int);

        wpr_acl_debug_dump_ip6_key_fields(&k_int);

        keys[0] = (const uint8_t *)&k_int;

        const uint32_t categories = 1;
        int rc = rte_acl_classify(ip6_ctx, keys, results, 1, categories);
        if (rc < 0)
            return rc;

        uint32_t userdata = results[0];

        if (userdata == 0) {
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        uint32_t idx = userdata - 1;
        if (idx >= WPR_ACL_MAX_RULES) {
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        wpr_acl_policy_tables_t *tables =
            atomic_load_explicit(&rt->policy_tables_curr,
                                memory_order_acquire);
        if (!tables) {
            res->hit            = false;
            res->default_policy = FLOW_ACT_NOOP;
            return 0;
        }

        *res = tables->ip6_actions[idx];

        if (!res->hit) {
            res->default_policy = FLOW_ACT_NOOP;
        }

        return 0;
    }

    /* Unknown family -> NOOP */
    res->hit = false;
    res->default_policy = FLOW_ACT_NOOP;
    return 0;
}

/** 
* Classify a non-IP L2 flow key against the ACL policy in the runtime structure.
* @param rt
*   Pointer to ACL runtime structure.
* @param l2_key
*   Pointer to L2 flow key structure.
* @param res
*   Pointer to output action/result structure.  
**/
int wpr_acl_classify_l2(const wpr_acl_runtime_t *rt,
                    const wpr_l2_flow_key_t *l2_key,
                    wpr_policy_action_t        *res)
{

    //guard against null pointers
    if (!rt || !l2_key){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR, "wpr_acl_classify_l2: invalid null pointer\n");
        return -EINVAL;
    }

    //make sure to zero out the result struct passed in
    memset(res, 0, sizeof(*res));

    //get L2 ACL control structure
    struct rte_acl_ctx *ctx = atomic_load_explicit(&rt->l2_acl_curr, memory_order_acquire);
    
    //if no L2 ACL context configured, default permit
    if (!ctx) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "No L2 ACL context configured, default NOOP\n");
        res->hit = false;
        res->default_policy = FLOW_ACT_NOOP;
        return 0;
    }

    //build internal key struct
    wpr_acl_l2_key_internal_t k_int;
    const uint8_t *keys[1];
    uint32_t results[1];

    wpr_acl_build_l2_key_internal(l2_key, &k_int);
    keys[0] = (const uint8_t *)&k_int;

    wpr_acl_debug_dump_l2_key_fields(&k_int);


    //call classify on single key
    const uint32_t categories = 1;
    int rc = rte_acl_classify(ctx, keys, results, 1, categories);
    if (rc < 0){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_ERR,
                "rte_acl_classify failed rc=%d (errno=%d)\n", rc, rte_errno);
        return rc;
    }
    uint32_t userdata = results[0];

    if (userdata == 0) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "L2 classification miss\n");
        res->hit            = false;
        res->default_policy = FLOW_ACT_NOOP;
        return 0;
    }

    uint32_t idx = userdata - 1;
    if (idx >= WPR_ACL_MAX_RULES) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "L2 classification index out of range\n");
        res->hit            = false;
        res->default_policy = FLOW_ACT_NOOP;
        return 0;
    }

    wpr_acl_policy_tables_t *tables = atomic_load_explicit(&rt->policy_tables_curr, memory_order_acquire);

    if (!tables) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "No policy tables configured, default NOOP\n");
        res->hit            = false;
        res->default_policy = FLOW_ACT_NOOP;
        return 0;
    }

    *res = tables->l2_actions[idx];

    if (!res->hit) {
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "L2 classification no hit, default NOOP\n");
        res->default_policy = FLOW_ACT_NOOP;
    }

    return 0;
}

int wpr_acl_stats_accumulator(wpr_acl_runtime_t *rt)
{
    if (!rt)
        return -EINVAL;

    //get global stats pointer safely 
    wpr_acl_rule_db_stats_t *global_stats = atomic_load_explicit(&rt->global_stats_curr, memory_order_acquire);
    if(!global_stats){
        WPR_LOG(WPR_LOG_ACL, RTE_LOG_DEBUG, "wpr_acl_stats_accumulator: invalid global stats pointer\n");
        return -EINVAL;
    }
    
    for (unsigned int i=0; i < rt->worker_cores ; i++){
        for (unsigned int j = 0; j < WPR_ACL_MAX_RULES; j++){
            //snapshot open / closed flows from each shard per type 
            //IPV4
            uint64_t newf = atomic_exchange_explicit(&rt->stats_shards[i].ip4[j].new_flows, 0, memory_order_relaxed);
            uint64_t closedf = atomic_exchange_explicit(&rt->stats_shards[i].ip4[j].closed_flows, 0, memory_order_relaxed);
            uint64_t cur = atomic_load_explicit(&global_stats->ip4[j].active_flows, memory_order_relaxed);
            uint64_t dec = closedf > cur ? cur : closedf;

            atomic_fetch_add_explicit(&global_stats->ip4[j].total_flows, newf, memory_order_relaxed);
            atomic_fetch_add_explicit(&global_stats->ip4[j].active_flows, newf, memory_order_relaxed);
            atomic_fetch_sub_explicit(&global_stats->ip4[j].active_flows, dec, memory_order_relaxed);

            //IPV6
            newf = atomic_exchange_explicit(&rt->stats_shards[i].ip6[j].new_flows, 0, memory_order_relaxed);
            closedf = atomic_exchange_explicit(&rt->stats_shards[i].ip6[j].closed_flows, 0, memory_order_relaxed);
            cur = atomic_load_explicit(&global_stats->ip6[j].active_flows, memory_order_relaxed);
            dec = closedf > cur ? cur : closedf;

            atomic_fetch_add_explicit(&global_stats->ip6[j].total_flows, newf, memory_order_relaxed);
            atomic_fetch_add_explicit(&global_stats->ip6[j].active_flows, newf, memory_order_relaxed);
            atomic_fetch_sub_explicit(&global_stats->ip6[j].active_flows, dec, memory_order_relaxed);

            //L2
            newf = atomic_exchange_explicit(&rt->stats_shards[i].l2[j].new_flows, 0, memory_order_relaxed);
            closedf = atomic_exchange_explicit(&rt->stats_shards[i].l2[j].closed_flows, 0, memory_order_relaxed);
            cur = atomic_load_explicit(&global_stats->l2[j].active_flows, memory_order_relaxed);
            dec = closedf > cur ? cur : closedf;

            atomic_fetch_add_explicit(&global_stats->l2[j].total_flows, newf, memory_order_relaxed);
            atomic_fetch_add_explicit(&global_stats->l2[j].active_flows, newf, memory_order_relaxed);
            atomic_fetch_sub_explicit(&global_stats->l2[j].active_flows, dec, memory_order_relaxed);
        }
    }
    return 0;
}
