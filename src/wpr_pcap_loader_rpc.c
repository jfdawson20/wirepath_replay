/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_pcap_loader_rpc.c
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

#include "wpr_pcap_loader_rpc.h"
#include "wpr_pcap_loader.h"
#include "wpr_app_defines.h"
#include "wpr_ports.h"
#include "wpr_tx_worker.h"
#include "wpr_log.h"


/* --- Internal helpers --- */

static inline uint32_t wpr_pcap_storage_published_count(const pcap_storage_t *st)
{
    /* Acquire not strictly required for the integer itself, but it's fine. */
    uint32_t n = atomic_load_explicit(&st->published_count, memory_order_acquire);
    if (n > WPR_MAX_PCAP_SLOTS) n = WPR_MAX_PCAP_SLOTS;
    return n;
}

static inline struct pcap_mbuff_slot *wpr_pcap_storage_get_slot(const pcap_storage_t *st, uint32_t slotid)
{
    if (slotid >= WPR_MAX_PCAP_SLOTS) return NULL;
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
int wpr_get_loaded_pcaps_list(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{
    (void)args;

    if (!reply_root || !thread_args || !thread_args->pcap_storage) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid arguments to wpr_get_loaded_pcaps_list\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    pcap_storage_t *st = thread_args->pcap_storage;

    /* published_count is monotonic allocation count; some slots may be NULL if a load failed before publish.
       We'll count only non-NULL published slots in the output list. */
    uint32_t max_slots = wpr_pcap_storage_published_count(st);

    json_t *arr = json_array();
    int active = 0;

    for (uint32_t i = 0; i < max_slots; i++) {
        struct pcap_mbuff_slot *slot = wpr_pcap_storage_get_slot(st, i);
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

        //add native metrics 
        json_object_set_new(pcap_info, "native_pps", json_real(slot->native_metrics.pps));
        json_object_set_new(pcap_info, "native_bps", json_real(slot->native_metrics.bps));
        json_object_set_new(pcap_info, "native_cps", json_real(slot->native_metrics.cps));

        //add last autotune info
        json_object_set_new(pcap_info, "last_autotune_kind", json_integer((json_int_t)slot->last_autotune.kind));
        json_object_set_new(pcap_info, "last_autotune_target", json_real(slot->last_autotune.target));
        json_object_set_new(pcap_info, "last_autotune_chosen_vc", json_integer((json_int_t)slot->last_autotune.chosen_vc));
        json_object_set_new(pcap_info, "last_autotune_predicted_total", json_real(slot->last_autotune.predicted_total));
        
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
static int check_pcap_status(wpr_thread_args_t *thread_args, int *result, unsigned int *slot)
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
int wpr_load_pcap_file(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
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
        struct pcap_mbuff_slot *slot = wpr_pcap_storage_get_slot(thread_args->pcap_storage, slotid);
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
        uint32_t max_slots = wpr_pcap_storage_published_count(thread_args->pcap_storage);
        printf("pcap loader: published_count=%u (max=%u)\n", max_slots, (unsigned)WPR_MAX_PCAP_SLOTS);

        for (uint32_t i = 0; i < max_slots; i++) {
            struct pcap_mbuff_slot *s = wpr_pcap_storage_get_slot(thread_args->pcap_storage, i);
            if (!s) continue;
            printf("Slot %u - File Loaded: %s, NumPackets: %u, Bytes: %lu\n",
                   i, s->pcap_name, s->numpackets, (unsigned long)s->size_in_bytes);
        }
    }

    return 0;
}


/** 
* Take a pcap slot ID assigned by the user and assign it to a port core for replay.
* @param thread_args
*   Pointer to the thread args structure.
* @param result
*   Pointer to integer to store result code (0=success, negative=error).
**/
int wpr_assign_port_slot(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{

    if (!reply_root || !args || !thread_args || !thread_args->pcap_storage || !thread_args->global_port_list) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid arguments to wpr_assign_port_slot\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    pcap_storage_t *st = thread_args->pcap_storage;
    wpr_ports_t *port_list = thread_args->global_port_list;

    //extract port number from command
    json_t *jportname = json_object_get(args, "port");
    if (!jportname) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'port' argument in wpr_assign_port_slot\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    const char *portname = json_string_value (jportname);


    //validate port entry exists
    wpr_port_entry_t *port_entry = wpr_find_port_byname(port_list, portname);
    if (!port_entry) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: could not find port entry for port name '%s'\n", portname);
        json_object_set_new(reply_root, "status", json_integer(-ENOENT));
        return -ENOENT;
    }

    //extract slot id from command
    json_t *jslotid = json_object_get(args, "slotid");
    if (!jslotid) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'slotid' argument in wpr_assign_port_slot\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    int slotid = (int)json_integer_value(jslotid);

    //validate slot exists
    uint32_t max_published_slots = atomic_load_explicit(&st->published_count, memory_order_acquire);
    if ((uint32_t)slotid >= max_published_slots) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: requested slotid %d is out of range (max published slots %u)\n",
                slotid, max_published_slots);
        json_object_set_new(reply_root, "status", json_integer(-ENOENT));
        return -ENOENT;
    }

    //get pointer to slot entry 
    pcap_mbuff_slot_t *slot_entry = atomic_load_explicit(&st->slots[slotid], memory_order_acquire);
    if (slot_entry == NULL) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: requested slotid %d is not loaded\n", slotid);
        json_object_set_new(reply_root, "status", json_integer(-ENOENT));
        return -ENOENT;
    }

    //extract pace mode from command 
    json_t *jpace_mode = json_object_get(args, "pace_mode");
    wpr_vc_pace_mode_t pace_mode = VC_PACE_NONE;
    if (jpace_mode) {
        pace_mode = (wpr_vc_pace_mode_t)json_integer_value(jpace_mode);
    }
    else { 
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_DEBUG, "No pace mode provided, defaulting to VC_PACE_NONE\n");
    }

    //extract start mode from command
    json_t *jstart_mode = json_object_get(args, "start_mode");
    wpr_vc_start_mode_t start_mode = VC_START_FIXED_INDEX; //default
    uint32_t start_index = 0;
    if (jstart_mode) {
        start_mode = (wpr_vc_start_mode_t)json_integer_value(jstart_mode);

        //if start mode is fixed index, extract fixed index value
        if (start_mode == VC_START_FIXED_INDEX){
            json_t *jfixed_index = json_object_get(args, "fixed_index");
            if (jfixed_index) {
                start_index = (uint32_t)json_integer_value(jfixed_index);
            }
            else {
                WPR_LOG(WPR_LOG_RPC, RTE_LOG_DEBUG, "No fixed index provided for VC_START_FIXED_INDEX mode, default to 0\n");
            }
        }
    }
    else {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_DEBUG, "No start mode provided, defaulting to VC_START_FIXED_INDEX - 0\n");   
    }

    if (start_mode == VC_START_FIXED_INDEX && start_index >= slot_entry->numpackets){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: fixed index %u is out of bounds for pcap slot %d with %u packets\n", 
                start_index, slotid, (unsigned int)slot_entry->numpackets);
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //extract the replay window in seconds - only used for paced modes
    json_t *jreplay_window_sec = json_object_get(args, "replay_window_sec");
    float replay_window_sec = 0;
    if (jreplay_window_sec) {
        replay_window_sec = (float)json_real_value(jreplay_window_sec);
    }

    if (pace_mode == VC_PACE_PCAP_TS && replay_window_sec == 0){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: replay window must be > 0 for VC_PACE_PCAP_TS mode\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //we now have the slot index and port entry. 
    uint16_t global_port_index = port_entry->global_port_index;

    //1) first disable tx on the port 
    atomic_store_explicit(&port_entry->tx_enabled, false, memory_order_release); 

    //2) assign the slot to the global port stream
    wpr_port_stream_global_t *port_streams = thread_args->port_stream_global_cfg;
    if(port_streams == NULL){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: port stream global config is NULL in wpr_assign_port_slot\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    atomic_store_explicit(&port_streams[global_port_index].slot_id, (uint32_t)slotid, memory_order_release);

    //3) set pace and start mode and start index 
    port_streams[global_port_index].pace_mode = pace_mode;
    port_streams[global_port_index].start_mode = start_mode;
    port_streams[global_port_index].stream_start_index = start_index;

    //4) set the replay window in ns
    uint64_t replay_window_ns = (uint64_t)(replay_window_sec * 1000000000ULL);
    if(pace_mode == VC_PACE_PCAP_TS && replay_window_ns < slot_entry->delta_ns){
        replay_window_ns = slot_entry->delta_ns;
    }
    port_streams[global_port_index].replay_window_ns = replay_window_ns;

    //5) set the global start time to 0 for now, it gets set when tx is enabled and first packet is sent
    port_streams[global_port_index].global_start_ns = 0;

    json_object_set_new(reply_root, "status", json_integer(0));
    return 0;  
}

