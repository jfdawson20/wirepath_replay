/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_pcap_loader_rpc.c
Description:
  RPC helpers for interacting with the pcap_loader thread and querying loaded PCAP slots.

  This version matches the fixed-max-slots + atomic publish model:
    - pcap_storage->slots[slotid] is an atomic pointer to a published slot
    - pcap_storage->published_count is an atomic count of allocated slot IDs (monotonic)
    - readers must use atomic_load_acquire when reading slot pointers
*/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>

#include "ppr_pcap_loader_rpc.h"
#include "ppr_pcap_loader.h"
#include "ppr_app_defines.h"


/* --- Internal helpers --- */

static inline uint32_t ppr_pcap_storage_published_count(const pcap_storage_t *st)
{
    /* Acquire not strictly required for the integer itself, but it's fine. */
    uint32_t n = atomic_load_explicit(&st->published_count, memory_order_acquire);
    if (n > PPR_MAX_PCAP_SLOTS) n = PPR_MAX_PCAP_SLOTS;
    return n;
}

static inline struct pcap_mbuff_slot *ppr_pcap_storage_get_slot(const pcap_storage_t *st, uint32_t slotid)
{
    if (slotid >= PPR_MAX_PCAP_SLOTS) return NULL;
    return atomic_load_explicit(&st->slots[slotid], memory_order_acquire);
}

/* Return a json list of all pcaps loaded into memory currently. Returns the following information for each
   active pcap storage slot:
   - slot id
   - pcap name
   - number of packets (mbufs) in the slot array
   - first/last/delta timestamps
   - size in bytes
*/
int ppr_get_loaded_pcaps_list(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args)
{
    (void)args;

    if (!reply_root || !thread_args || !thread_args->pcap_storage) {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    pcap_storage_t *st = thread_args->pcap_storage;

    /* published_count is monotonic allocation count; some slots may be NULL if a load failed before publish.
       We'll count only non-NULL published slots in the output list. */
    uint32_t max_slots = ppr_pcap_storage_published_count(st);

    json_t *arr = json_array();
    int active = 0;

    for (uint32_t i = 0; i < max_slots; i++) {
        struct pcap_mbuff_slot *slot = ppr_pcap_storage_get_slot(st, i);
        if (!slot)
            continue;

        json_t *pcap_info = json_object();

        json_object_set_new(pcap_info, "slotid",       json_integer((json_int_t)i));
        json_object_set_new(pcap_info, "pcap_name",    json_string(slot->pcap_name));
        json_object_set_new(pcap_info, "pcap_packets", json_integer((json_int_t)slot->numpackets));
        json_object_set_new(pcap_info, "first_ns",     json_integer((json_int_t)slot->start_ns));
        json_object_set_new(pcap_info, "last_ns",      json_integer((json_int_t)slot->end_ns));
        json_object_set_new(pcap_info, "delta_ns",     json_integer((json_int_t)slot->delta_ns));
        json_object_set_new(pcap_info, "size_in_bytes",json_integer((json_int_t)slot->size_in_bytes));
        json_object_set_new(pcap_info, "mode",         json_integer((json_int_t)slot->mode));

        json_array_append_new(arr, pcap_info);
        active++;
    }

    json_object_set_new(reply_root, "status", json_integer(0));
    json_object_set_new(reply_root, "num_pcaps", json_integer(active));
    json_object_set_new(reply_root, "loaded_pcaps", arr);
    return 0;
}

/* check for pcap loading complete - polls pcap thread control structure
   returns 0 if busy and 1 if done. slot ID loaded and result (error) returned in pointers
*/
static int check_pcap_status(ppr_thread_args_t *thread_args, int *result, unsigned int *slot)
{
    int done = 0;

    pthread_mutex_lock(&thread_args->pcap_controller->lock);
    if (!thread_args->pcap_controller->busy &&
        thread_args->pcap_controller->command == CMD_NONE) {
        *result = thread_args->pcap_controller->result;
        *slot   = thread_args->pcap_controller->latest_slotid;
        done = 1;
    }
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);
    return done;
}

/* Primary pcap load command handler. Kicks the pcap_loader pthread and blocks until complete. */
int ppr_load_pcap_file(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args)
{
    if (!reply_root || !args || !thread_args || !thread_args->pcap_controller || !thread_args->pcap_storage) {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    /* extract filename from command */
    json_t *jfn = json_object_get(args, "filename");
    const char *filename = jfn ? json_string_value(jfn) : NULL;
    if (!filename || filename[0] == '\0') {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        json_object_set_new(reply_root, "error", json_string("missing or empty 'filename'"));
        return -EINVAL;
    }

    /* Kick loader thread */
    pthread_mutex_lock(&thread_args->pcap_controller->lock);

    /* If loader is busy, return a clean error */
    if (thread_args->pcap_controller->busy) {
        pthread_mutex_unlock(&thread_args->pcap_controller->lock);
        json_object_set_new(reply_root, "status", json_integer(-EBUSY));
        json_object_set_new(reply_root, "error", json_string("pcap loader is busy"));
        return -EBUSY;
    }

    snprintf(thread_args->pcap_controller->filename,
             sizeof(thread_args->pcap_controller->filename),
             "%s", filename);

    thread_args->pcap_controller->command = CMD_LOAD_PCAP;
    thread_args->pcap_controller->busy = true; /* defensive: loader sets it too */
    pthread_cond_signal(&thread_args->pcap_controller->cond);
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);

    /* Wait for load to complete */
    int pcap_error = 0;
    unsigned int slotid = 0;

    while (check_pcap_status(thread_args, &pcap_error, &slotid) == 0) {
        usleep(10 * 1000);
    }

    /* Validate slot publication if load succeeded */
    int numpackets = 0;
    if (pcap_error == 0) {
        struct pcap_mbuff_slot *slot = ppr_pcap_storage_get_slot(thread_args->pcap_storage, slotid);
        if (!slot) {
            /* This should not happen if loader publishes slot before setting result=0,
               but handle defensively. */
            pcap_error = -EIO;
        } else {
            numpackets = (int)slot->numpackets;
        }
    }

    /* format result */
    json_object_set_new(reply_root, "status", json_integer(pcap_error));
    json_object_set_new(reply_root, "slot", json_integer((json_int_t)slotid));
    json_object_set_new(reply_root, "num_packets", json_integer(numpackets));

    /* Optional debug print of all currently published slots */
    {
        uint32_t max_slots = ppr_pcap_storage_published_count(thread_args->pcap_storage);
        printf("pcap loader: published_count=%u (max=%u)\n", max_slots, (unsigned)PPR_MAX_PCAP_SLOTS);

        for (uint32_t i = 0; i < max_slots; i++) {
            struct pcap_mbuff_slot *s = ppr_pcap_storage_get_slot(thread_args->pcap_storage, i);
            if (!s) continue;
            printf("Slot %u - File Loaded: %s, NumPackets: %u, Bytes: %lu\n",
                   i, s->pcap_name, s->numpackets, (unsigned long)s->size_in_bytes);
        }
    }

    return 0;
}
