/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_actions.h
Description: header file containing app wide constants and structs around flow actions and global policies. 

*/
#include <netinet/in.h>
#include <rte_ether.h>

#include "ppr_log.h"

#ifndef PPR_ACTIONS_H
#define PPR_ACTIONS_H


//Enum for flow action kinds - keep < 8 bits
typedef enum ppr_flow_action_kind {
    FLOW_ACT_NOOP           = 0, //no modifications 
    FLOW_ACT_DROP           = 1, //drop packet
    FLOW_ACT_MODIFY_SRCMAC  = 2, //modify source mac
    FLOW_ACT_MODIFY_SRCIP   = 3, //modify source ip
    FLOW_ACT_MODIFY_SRCPORT = 4, //modify source port
    FLOW_ACT_MODIFY_SRC_ALL = 5,
    FLOW_ACT_MODIFY_DSTMAC  = 6, //modify dest mac
    FLOW_ACT_MODIFY_DSTIP   = 7, //modify dest ip
    FLOW_ACT_MODIFY_DSTPORT = 8, //modify dest port
    FLOW_ACT_MODIFY_DST_ALL = 9,
    FLOW_ACT_MODIFY_ALL     = 10,
    FLOW_ACT_MAX_
} ppr_flow_action_kind_t;


typedef struct ppr_policy_action {
    bool                    valid;    
    bool                    hit;       //true if matched a rule, false if default action         
    uint32_t                idx; 
    uint32_t                priority;      
    ppr_flow_action_kind_t  default_policy;
} ppr_policy_action_t;


/* Global Policy Epoch Variables */
typedef struct ppr_global_policy_epoch{
    _Atomic uint64_t acl_policy_epoch;
    _Atomic uint64_t pcap_storage_epoch;
} ppr_global_policy_epoch_t;


static inline const char *ppr_flow_action_kind_to_str(ppr_flow_action_kind_t kind){
    switch(kind){
        case FLOW_ACT_NOOP:           return "NOOP";
        case FLOW_ACT_DROP:           return "DROP";
        case FLOW_ACT_MODIFY_SRCMAC:  return "MODIFY_SRCMAC";
        case FLOW_ACT_MODIFY_SRCIP:   return "MODIFY_SRCIP";
        case FLOW_ACT_MODIFY_SRCPORT: return "MODIFY_SRCPORT";  
        case FLOW_ACT_MODIFY_SRC_ALL: return "MODIFY_SRC_ALL";
        case FLOW_ACT_MODIFY_DSTMAC:  return "MODIFY_DSTMAC";
        case FLOW_ACT_MODIFY_DSTIP:   return "MODIFY_DSTIP";
        case FLOW_ACT_MODIFY_DSTPORT: return "MODIFY_DSTPORT";
        case FLOW_ACT_MODIFY_DST_ALL: return "MODIFY_DST_ALL";
        case FLOW_ACT_MODIFY_ALL:     return "MODIFY_ALL";
        default:                      return "UNKNOWN";
    }
}

/** 
* Print the action part of an ACL rule for debugging.
* @param a Pointer to the ACL policy action to print.
**/
static inline void ppr_acl_print_action(const ppr_policy_action_t *a)
{
    if (!a)
        return;

    PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
            "    action: policy=%s (%d)\n",
            ppr_flow_action_kind_to_str(a->default_policy),
            (int)a->default_policy);

}

#endif