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
            free(slot->mbuf_array);
            slot->mbuf_array = NULL;
        }
        free(slot);

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
    struct rte_mbuf *m = *pmbuf;
    uint32_t remaining = len;

    while (remaining) {
        struct rte_mbuf *last = rte_pktmbuf_lastseg(m);
        uint32_t tailroom = rte_pktmbuf_tailroom(last);

        if (tailroom == 0) {
            struct rte_mbuf *seg = rte_pktmbuf_alloc(mp);
            if (!seg) return -ENOMEM;
            seg->next = NULL;
            seg->data_len = 0;
            last->next = seg;
            m->nb_segs++;
            last = seg;
            tailroom = rte_pktmbuf_tailroom(last);
        }

        uint32_t to_copy = remaining < tailroom ? remaining : tailroom;
        uint8_t *dst = rte_pktmbuf_mtod_offset(last, uint8_t *, last->data_len);
        rte_memcpy(dst, src + (len - remaining), to_copy);
        last->data_len += to_copy;
        m->pkt_len   += to_copy;
        remaining    -= to_copy;
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

/*
 * Build a new slot privately and publish it.
 * - Allocates mbuf_array and slot struct
 * - Reads PCAP, fills mbufs
 * - Publishes slot pointer atomically when complete
 */
static int process_pcap(ppr_thread_args_t *thread_args, const char *filename) {
    if (!thread_args || !filename) return -EINVAL;

    const uint8_t *data = NULL;
    struct pcap_pkthdr *hdr = NULL;
    int rc;

    uint64_t first_ns = 0, last_ns = 0;
    uint64_t total_bytes = 0;

    struct rte_mempool *mp = thread_args->pcap_template_mpool;
    struct pcap_storage *st = thread_args->pcap_storage;

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

    /* Open PCAP */
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *pc = pcap_open_offline_with_tstamp_precision(filename, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!pc) {
        pc = pcap_open_offline(filename, errbuf);
        if (!pc) {
            fprintf(stderr, "pcap open failed: %s\n", errbuf);
            free(mbuff_array);
            return -EINVAL;
        }
    }
    int prec = pcap_get_tstamp_precision(pc);

    /* Enforce Ethernet */
    int dlt = pcap_datalink(pc);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type (DLT=%d). Expected DLT_EN10MB.\n", dlt);
        pcap_close(pc);
        mbuf_array_free(mbuff_array);
        free(mbuff_array);
        return -ENOTSUP;
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
        if (!m) {
            fprintf(stderr, "mbuf alloc failed (rte_errno=%d)\n", rte_errno);
            pcap_close(pc);
            mbuf_array_free(mbuff_array);
            free(mbuff_array);
            return -ENOMEM;
        }

        m->data_len = 0;
        m->pkt_len  = 0;
        m->nb_segs  = 1;
        m->next     = NULL;

        my_ts_set(m, thread_args->mbuf_ts_off, ns - first_ns);

        if (append_bytes_to_mbuf(&m, mp, data, caplen) != 0) {
            rte_pktmbuf_free(m);
            pcap_close(pc);
            mbuf_array_free(mbuff_array);
            rte_free(mbuff_array);
            return -ENOMEM;
        }

        mbuf_array_push(mbuff_array, m);
    }

    pcap_close(pc);

    /* Build the slot privately */
    struct pcap_mbuff_slot *slot = rte_zmalloc("pcap_mbuff_slot", sizeof(*slot), RTE_CACHE_LINE_SIZE);
    if (!slot) {
        mbuf_array_free(mbuff_array);
        rte_free(mbuff_array);
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

    return 0;
}

/**
 * Iterate through loaded pcaps and apply ACL rules to each packet, storing policy decision in mbuf private area
 * NOTE: You can safely run this only on slots that are already published and immutable in shape.
 * If you plan to mutate per-packet metadata arrays, prefer allocating meta arrays once and writing them
 * before publishing, OR gate ACL processing to STOPPED state.
 */
int process_acl_on_loaded_pcap(struct pthread_args *thread_args, unsigned int slotid) {
    (void)thread_args;
    (void)slotid;
    return 0;
}

/* Main loader thread */
void *run_pcap_loader_thread(void *arg) {
    ppr_thread_args_t *thread_args  = (ppr_thread_args_t *)arg;
    struct pcap_loader_ctl *ctl = thread_args->pcap_controller;

    pcap_storage_init(thread_args->pcap_storage);

    pthread_mutex_lock(&ctl->lock);

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
