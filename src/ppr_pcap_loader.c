/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: pcap_loader.c
Description:
  Pcap loader pthread. Loads PCAP files into a template mbuf array and publishes
  completed PCAP "slots" to a fixed-size global slot table using atomic pointer
  publication. This allows readers (tx workers) to safely access loaded pcaps
  concurrently without races from realloc().

  Concurrency model:
    - Loader builds slot privately (including mbuf array growth via realloc()).
    - After build is complete and immutable, loader publishes slot pointer with
      atomic_store_release().
    - Readers obtain slot pointers with atomic_load_acquire().
    - Slots are never deleted during runtime; freed only at shutdown.

  Max slots: 256
*/

#include <pcap/pcap.h>
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "rte_malloc.h"

#include "ppr_pcap_loader.h"
#include "ppr_app_defines.h"
#include "ppr_mbuf_fields.h"
#include "ppr_control.h"
#include "ppr_acl_yaml.h"
#include "ppr_log.h"
#include "ppr_acl.h"
#include "ppr_flowkey.h"
#include "ppr_header_extract.h"


/* ------------------------------- dynamic mbuf array functions -------------------------- */

static void mbuf_array_init(struct mbuf_array *arr) {
    arr->pkts = NULL;
    arr->count = 0;
    arr->capacity = 0;
    arr->cap_ts_us = NULL;
    arr->action_id = NULL;
}

static void mbuf_array_push(struct mbuf_array *arr, struct rte_mbuf *m) {
    if (arr->count == arr->capacity) {
        size_t newcap = (arr->capacity == 0) ? 1024 : arr->capacity * 2;
        struct rte_mbuf **newpkts = rte_realloc(arr->pkts, newcap * sizeof(*newpkts), RTE_CACHE_LINE_SIZE);
        if (!newpkts) {
            perror("realloc failed");
            exit(EXIT_FAILURE);
        }
        arr->pkts = newpkts;
        arr->capacity = newcap;
    }
    arr->pkts[arr->count++] = m;
}

static void mbuf_array_free(struct mbuf_array *arr) {
    if (!arr) return;
    for (size_t i = 0; i < arr->count; i++) {
        if (arr->pkts[i])
            rte_pktmbuf_free(arr->pkts[i]);
    }
    rte_free(arr->pkts);
    arr->pkts = NULL;
    arr->count = 0;
    arr->capacity = 0;

    /* If you later allocate these arrays, free them here too */
    rte_free((void*)arr->cap_ts_us);
    rte_free((void*)arr->action_id);
    arr->cap_ts_us = NULL;
    arr->action_id = NULL;
}

/* ------------------------------- pcap storage functions (fixed slots + atomic publish) -------------------------- */

static void pcap_storage_init(struct pcap_storage *st) {
    if (!st) return;
    for (unsigned i = 0; i < PPR_MAX_PCAP_SLOTS; i++) {
        atomic_store_explicit(&st->slots[i], NULL, memory_order_relaxed);
    }
    atomic_store_explicit(&st->published_count, 0, memory_order_relaxed);
}

/* Allocate a new slot id (monotonic). Returns 0 on success, -ENOSPC if full. */
static int pcap_storage_alloc_slotid(struct pcap_storage *st, unsigned int *slotid_out) {
    if (!st || !slotid_out) return -EINVAL;

    uint32_t id = atomic_fetch_add_explicit(&st->published_count, 1, memory_order_relaxed);
    if (id >= PPR_MAX_PCAP_SLOTS) {
        /* roll back (best-effort). If multiple threads allocate, you might not want rollback;
           here only loader allocates so rollback is safe-ish. */
        atomic_fetch_sub_explicit(&st->published_count, 1, memory_order_relaxed);
        return -ENOSPC;
    }
    *slotid_out = (unsigned int)id;
    return 0;
}

/* Publish a fully constructed slot pointer. Must be immutable after publish. */
static inline void pcap_storage_publish_slot(struct pcap_storage *st,
                                            unsigned int slotid,
                                            struct pcap_mbuff_slot *slot)
{
    /* One-way publish. Readers use acquire. */
    atomic_store_explicit(&st->slots[slotid], slot, memory_order_release);
}

/* Free all published slots at shutdown (no concurrent readers). */
static void pcap_storage_free(struct pcap_storage *st) {
    if (!st) return;

    uint32_t max = atomic_load_explicit(&st->published_count, memory_order_relaxed);
    if (max > PPR_MAX_PCAP_SLOTS) max = PPR_MAX_PCAP_SLOTS;

    for (uint32_t i = 0; i < max; i++) {
        struct pcap_mbuff_slot *slot =
            atomic_load_explicit(&st->slots[i], memory_order_relaxed);
        if (!slot) continue;

        if (slot->mbuf_array) {
            mbuf_array_free(slot->mbuf_array);
            rte_free(slot->mbuf_array);
            slot->mbuf_array = NULL;
        }
        rte_free(slot);

        atomic_store_explicit(&st->slots[i], NULL, memory_order_relaxed);
    }
    atomic_store_explicit(&st->published_count, 0, memory_order_relaxed);
}

/* -------------------------------------------- Primary Pcap Loading / Processing Functions ----------------------------------- */

static inline int append_bytes_to_mbuf(struct rte_mbuf **pmbuf,
                                      struct rte_mempool *mp,
                                      const uint8_t *src,
                                      uint32_t len)
{
    if (!pmbuf || !*pmbuf || !mp || (!src && len))
        return -EINVAL;

    struct rte_mbuf *m = *pmbuf;
    uint32_t off = 0;

    while (off < len) {
        struct rte_mbuf *last = rte_pktmbuf_lastseg(m);
        uint32_t tail = rte_pktmbuf_tailroom(last);

        if (tail == 0) {
            struct rte_mbuf *seg = rte_pktmbuf_alloc(mp);
            if (!seg) return -ENOMEM;
            rte_pktmbuf_reset(seg);

            if (rte_pktmbuf_chain(m, seg) != 0) {
                rte_pktmbuf_free(seg);
                return -ENOMEM;
            }
            continue;
        }

        uint32_t to_copy = (len - off < tail) ? (len - off) : tail;
        char *dst = rte_pktmbuf_append(m, to_copy);
        if (!dst) return -ENOSPC;

        rte_memcpy(dst, src + off, to_copy);
        off += to_copy;
    }

    return 0;
}


static uint64_t ts_to_ns(const struct pcap_pkthdr *h, int prec) {
    uint64_t sec_ns = (uint64_t)h->ts.tv_sec * 1000000000ull;
    uint64_t sub    = (prec == PCAP_TSTAMP_PRECISION_NANO)
                        ? (uint64_t)h->ts.tv_usec               /* tv_usec holds ns in nano mode */
                        : (uint64_t)h->ts.tv_usec * 1000ull;    /* micro -> nano */
    return sec_ns + sub;
}

/** 
* Process ACL lookups for a given mbuf and populate the mbuf private area with the resulting action.    
* @param acl_runtime_ctx
*   Pointer to ACL runtime context structure.
* @param acl_db
*   Pointer to ACL rule database structure.
* @param m
*   Pointer to mbuf to process.
* @param hdrs
*   Pointer to parsed headers structure.
* @param ip_flowkey_valid
*   Boolean indicating if the IP flow key is valid.
* @param ip_flow_key
*   Pointer to IP flow key structure.
* @param l2_flowkey_valid
*   Boolean indicating if the L2 flow key is valid.
* @param l2_flow_key
*   Pointer to L2 flow key structure.
**/
static inline void process_acl_lookup(ppr_acl_runtime_t *acl_runtime_ctx,
                                      ppr_acl_rule_db_t *acl_db,
                                      struct rte_mbuf *m,
                                      ppr_hdrs_t *hdrs,
                                      bool ip_flowkey_valid,
                                      const ppr_flow_key_t *ip_flow_key,
                                      bool l2_flowkey_valid,
                                      const ppr_l2_flow_key_t *l2_flow_key)
{

    (void)acl_db; //unused for now
    ppr_policy_action_t ip_acl_action = {0};
    ppr_policy_action_t l2_acl_action = {0};

    ppr_priv_t *priv = ppr_priv(m);
    int rc = 0;

    if (!acl_runtime_ctx || !hdrs) {
        PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Null argument passed to process_acl_lookup\n");
        return;
    }


    //perform ACL lookups into both tables if we have valid flow keys
    //lookup l2 action if we have a valid l2 flow key
    if(l2_flow_key && l2_flowkey_valid){
        rc = ppr_acl_classify_l2(acl_runtime_ctx,
                                 l2_flow_key,
                                 &l2_acl_action);

        if (rc < 0) {
            PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR,"ACL L2 lookup failed with error %d\n", rc);
            return;
        }
    }

    //now L3 lookup if we have a valid ip flow key
    if(ip_flow_key && ip_flowkey_valid){
        rc = ppr_acl_classify_ip(acl_runtime_ctx,
                                 ip_flow_key,
                                 m->port,
                                 &ip_acl_action);

        if (rc < 0) {
            PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR,"ACL lookup failed with error %d\n", rc);
            return;
        }
    }

    //if we only have one valid policy, apply that, else go by priority
    ppr_policy_action_t *selected_action = NULL;
    bool is_l2_action = false;
    if(l2_acl_action.hit && !ip_acl_action.hit){
        PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO,
                "L2 ACL matched: applying action\n");

        selected_action = &l2_acl_action;
        is_l2_action = true;

    }
    else if (ip_acl_action.hit && !l2_acl_action.hit){
        PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO,
                "IP ACL matched: applying action\n");

        selected_action = &ip_acl_action;
        is_l2_action = false;
    }
    else if (l2_acl_action.hit && ip_acl_action.hit){
        //both hit, choose by priority
        if (l2_acl_action.priority >= ip_acl_action.priority){
            PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO,
                    "Both L2 and IP ACL matched: applying L2 action due to higher priority\n");

            selected_action = &l2_acl_action;
            is_l2_action = true;
        }
        else{
            PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO,
                    "Both L2 and IP ACL matched: applying IP action due to higher priority\n");

            selected_action = &ip_acl_action;
            is_l2_action = false;
        }
    }
    else{
        //no hits
        PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO,
                "No ACL match found\n");
        return;
    }


    //now that we've resolved our policy action, apply it to the priv area
    priv->pending_policy_action = *selected_action;

    //store the selected action index
    priv->acl_policy_index = selected_action->idx;

    //set the correct L3 type field for later use
    if(is_l2_action)
        priv->acl_policy_type = PPR_L3_NONE;
    else
    priv->acl_policy_type = hdrs->l3_type;

    return;

}


/*
 * Build a new slot privately and publish it.
 * - Allocates mbuf_array and slot struct
 * - Reads PCAP, fills mbufs
 * - Publishes slot pointer atomically when complete
 */
static int process_pcap(ppr_thread_args_t *thread_args, const char *filename) {
    if (!thread_args || !filename) 
        return -EINVAL;

    ppr_acl_rule_db_t *acl_db = thread_args->acl_rule_db;
    ppr_ports_t *global_port_list = thread_args->global_port_list;

    if(!acl_db || !global_port_list){
        return -EINVAL;
    }

    const uint8_t *data = NULL;
    struct pcap_pkthdr *hdr = NULL;
    int rc;

    uint64_t first_ns = 0, last_ns = 0;
    uint64_t total_bytes = 0;

    struct rte_mempool *mp = thread_args->pcap_template_mpool;
    struct pcap_storage *st = thread_args->pcap_storage;

    /* Parse yaml file */
    char *pcap_filepath_out=NULL;
    rc = ppr_acl_load_startup_file(filename,acl_db,global_port_list,&pcap_filepath_out);
    if (rc < 0) {
        fprintf(stderr, "Failed to parse ACL YAML file %s: rc=%d\n", filename, rc);
        return rc;
    }
    if (pcap_filepath_out == NULL || *pcap_filepath_out == '\0') {
        fprintf(stderr, "No pcap template filepath found in ACL YAML file %s\n", filename);
        return -EINVAL;
    }

    /* Open PCAP */
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *pc = pcap_open_offline_with_tstamp_precision(pcap_filepath_out, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!pc) {
        pc = pcap_open_offline(pcap_filepath_out, errbuf);
        if (!pc) {
            fprintf(stderr, "pcap open failed: %s\n", errbuf);
            free(pcap_filepath_out);
            return -EINVAL;
        }
    }
    int prec = pcap_get_tstamp_precision(pc);


    /* Allocate slot id up front (monotonic). */
    unsigned int slotid = 0;
    int s_rc = pcap_storage_alloc_slotid(st, &slotid);
    if (s_rc != 0) {
        fprintf(stderr, "pcap_storage full (max=%u)\n", PPR_MAX_PCAP_SLOTS);
        return s_rc;
    }

    /* Build mbuf array privately */
    struct mbuf_array *mbuff_array = rte_zmalloc("mbuf_array", sizeof(*mbuff_array), RTE_CACHE_LINE_SIZE);
    if (!mbuff_array) return -ENOMEM;
    mbuf_array_init(mbuff_array);

    /* Enforce Ethernet */
    int dlt = pcap_datalink(pc);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type (DLT=%d). Expected DLT_EN10MB.\n", dlt);
        pcap_close(pc);
        mbuf_array_free(mbuff_array);
        rte_free(mbuff_array);
        free(pcap_filepath_out);
        return -ENOTSUP;
    }

    //commit acl rules to runtime before processing pcap
    rc = ppr_acl_db_commit(thread_args->acl_runtime, thread_args->acl_rule_db);
    if (rc != 0){
        rte_exit(EXIT_FAILURE, "Failed to commit loaded ACL rules to runtime\n");
    }

    bool have_first = false;

    while ((rc = pcap_next_ex(pc, &hdr, &data)) >= 0) {
        if (rc == 0) continue;

        uint64_t ns = ts_to_ns(hdr, prec);
        if (!have_first) {
            first_ns = ns;
            have_first = true;
        }
        last_ns = ns;

        const uint32_t caplen = hdr->caplen;
        total_bytes += caplen;

        struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
        if (unlikely(m->buf_addr == NULL)) {
            free(pcap_filepath_out);
            return -EINVAL;
        }

        //reset so we have a clean priv area
        rte_pktmbuf_reset(m);

        //set the timestamp 
        my_ts_set(m, thread_args->mbuf_ts_off, ns - first_ns);

        if (append_bytes_to_mbuf(&m, mp, data, caplen) != 0) {
            rte_pktmbuf_free(m);
            pcap_close(pc);
            mbuf_array_free(mbuff_array);
            rte_free(mbuff_array);
            free(pcap_filepath_out);
            return -ENOMEM;
        }

        
        //parse header structure from packet
        ppr_hdrs_t hdrs; 
        rc = ppr_parse_headers(m, &hdrs);
        if (rc < 0) {
            PPR_LOG(PPR_LOG_DP, RTE_LOG_ERR, "Failed to parse headers for ACL lookup\n");
            rte_pktmbuf_free(m);
            pcap_close(pc);
            mbuf_array_free(mbuff_array);
            rte_free(mbuff_array);
            free(pcap_filepath_out);
            return rc;
        }

        //build flow keys 
        bool l2_flowkey_valid = false;
        ppr_l2_flow_key_t l2_flow_key = {0};
    
        rc = ppr_l2_flowkey_from_hdr(&hdrs, &l2_flow_key, slotid);
        if (rc == 0){
            l2_flowkey_valid = true;
        }

        bool ip_flowkey_valid = false;
        ppr_flow_key_t ip_flow_key = {0};
        rc = ppr_flowkey_from_hdr( &hdrs, &ip_flow_key, slotid);
        if(rc == 0){
            ip_flowkey_valid = true;
        }

        if(!ip_flowkey_valid && !l2_flowkey_valid){
            PPR_LOG(PPR_LOG_DP, RTE_LOG_INFO, "No valid flow keys could be built for ACL lookup\n");
        }
        //process acl lookup and populate mbuf priv area
        process_acl_lookup(thread_args->acl_runtime,
                           acl_db,
                           m,
                           &hdrs,
                           ip_flowkey_valid,
                           &ip_flow_key,
                           l2_flowkey_valid,
                           &l2_flow_key);
       

        mbuf_array_push(mbuff_array, m);
    }

    pcap_close(pc);

    /* Build the slot privately */
    struct pcap_mbuff_slot *slot = rte_zmalloc("pcap_mbuff_slot", sizeof(*slot), RTE_CACHE_LINE_SIZE);
    if (!slot) {
        mbuf_array_free(mbuff_array);
        rte_free(mbuff_array);
        free(pcap_filepath_out);
        return -ENOMEM;
    }

    snprintf(slot->pcap_name, sizeof(slot->pcap_name), "%s", filename);
    slot->numpackets    = (unsigned int)mbuff_array->count;
    slot->mbuf_array    = mbuff_array;
    slot->start_ns      = first_ns;
    slot->end_ns        = last_ns;
    slot->delta_ns      = last_ns - first_ns;
    slot->size_in_bytes = total_bytes;
    slot->mode          = UNASSIGNED;

    /* Publish the slot pointer atomically.
     * After this point, do not mutate slot or mbuff_array fields.
     */
    pcap_storage_publish_slot(st, slotid, slot);

    /* Update controller visible latest slot id */
    thread_args->pcap_controller->latest_slotid = slotid;
    free(pcap_filepath_out);
    return 0;
}

/* Main loader thread */
void *run_pcap_loader_thread(void *arg) {
    ppr_thread_args_t *thread_args  = (ppr_thread_args_t *)arg;
    struct pcap_loader_ctl *ctl = thread_args->pcap_controller;

    pcap_storage_init(thread_args->pcap_storage);

    pthread_mutex_lock(&ctl->lock);

    //mark thread ready
    atomic_store_explicit(&thread_args->thread_ready, true, memory_order_relaxed);

    //wait for app ready flag from main thread
    while (atomic_load_explicit(thread_args->app_ready, memory_order_relaxed) == false) {
        rte_pause();
    }

    while (1) {
        while (ctl->command == CMD_NONE) {
            pthread_cond_wait(&ctl->cond, &ctl->lock);
        }

        if (ctl->command == CMD_EXIT) {
            pthread_mutex_unlock(&ctl->lock);
            break;
        }

        if (ctl->command == CMD_LOAD_PCAP) {
            ctl->busy = true;

            char file[256];
            snprintf(file, sizeof(file), "%s", ctl->filename);

            ctl->command = CMD_NONE;

            pthread_mutex_unlock(&ctl->lock);

            int rc = process_pcap(thread_args, file);

            pthread_mutex_lock(&ctl->lock);
            ctl->result = rc;
            ctl->busy = false;
        }

        /* Add CMD_APPLY_ACL_RULES handling here if desired */
    }

    /* Shutdown: no concurrent readers should remain */
    pcap_storage_free(thread_args->pcap_storage);
    return NULL;
}
