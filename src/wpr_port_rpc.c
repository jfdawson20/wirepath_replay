
#include <math.h>

#include "wpr_port_rpc.h"
#include "wpr_tx_worker.h"
#include "wpr_time.h"

int wpr_cmd_get_port_list(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args){
    //silence unused param warnings
    (void)args;
    wpr_ports_t *port_list = thread_args->global_port_list;
    json_t *portlist = json_object();

    WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "\n Dumping Global Port List: num_ports=%u\n", port_list->num_ports);
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        json_t *portentry = json_object();
        json_t *rx_queue_arr = json_array();
        json_t *tx_queue_arr = json_array();
        int rc = 0;

        char direction[32];
        if (port_list->ports[i].dir == WPR_PORT_RX){
            snprintf(direction, sizeof(direction), "RX");
        }
        else if (port_list->ports[i].dir == WPR_PORT_TX){
            snprintf(direction, sizeof(direction), "TX");
        }
        else {
            snprintf(direction, sizeof(direction), "RXTX");
        }

        const char *name = port_list->ports[i].name;
        uint16_t port_id = port_list->ports[i].port_id;
        const char *is_external = port_list->ports[i].is_external ? "true" : "false";
        uint16_t total_rx_queues = port_list->ports[i].total_rx_queues;
        uint16_t total_tx_queues = port_list->ports[i].total_tx_queues;
        
        rc += json_object_set_new(portentry, "name", json_string(name));
        rc += json_object_set_new(portentry, "port_id", json_integer(port_id));
        rc += json_object_set_new(portentry, "is_external", json_string(is_external));
        rc += json_object_set_new(portentry, "total_rx_queues", json_integer(total_rx_queues));
        rc += json_object_set_new(portentry, "total_tx_queues", json_integer(total_tx_queues));
        rc += json_object_set_new(portentry, "dir", json_string(direction));

        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tRX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_rx_queues; q++){
            json_t *rx_queue_entry = json_object();
            rc += json_object_set_new(rx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(rx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].rx_queue_assignments[q]));
            rc += json_array_append_new(rx_queue_arr,rx_queue_entry);
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].rx_queue_assignments[q]);
        }
        
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
        
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tTX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_tx_queues; q++){
            json_t *tx_queue_entry = json_object();
            rc += json_object_set_new(tx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(tx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].tx_queue_assignments[q]));
            rc += json_array_append_new(tx_queue_arr,tx_queue_entry);
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].tx_queue_assignments[q]);
        }
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
        rc += json_object_set_new(portentry, "rx_queues", rx_queue_arr);
        rc += json_object_set_new(portentry, "tx_queues", tx_queue_arr);
        rc += json_object_set_new(portlist,name, portentry);
    }

    int rc = 0;
    rc = json_object_set_new(reply_root, "port_list", portlist);
    if (rc < 0){
        return -EINVAL;
    }
    
    return 0;
}


/** 
* Handle RPC command to enable or disable TX on a port.
* @param reply_root
*   JSON object to populate with reply.
* @param args
*   JSON object containing command arguments.
* @param thread_args
*   Pointer to pthread args structure.
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int wpr_port_tx_ctl(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args){

    wpr_ports_t *global_port_list = thread_args->global_port_list;

    //extract port name from command
    json_t *jportname = json_object_get(args, "port");
    if (!jportname) {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    const char *portname = json_string_value (jportname);

    //validate port entry exists
    wpr_port_entry_t *port_entry = wpr_find_port_byname(global_port_list, portname);
    if (!port_entry) {
        json_object_set_new(reply_root, "status", json_integer(-ENOENT));
        return -ENOENT;
    }

    //extract enable/disable command
    json_t *jcmd = json_object_get(args, "cmd");
    if (!jcmd) {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    const char *cmd_str = json_string_value(jcmd);

    uint16_t global_port_index = port_entry->global_port_index;

    //get global port stream config for this port
    wpr_port_stream_global_t *port_streams = thread_args->port_stream_global_cfg;
    if(port_streams == NULL){
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    
    //verify stream has a valid slot assignment for enable only
    uint32_t slot_id = atomic_load_explicit(&port_streams[global_port_index].slot_id, memory_order_acquire);
    if (slot_id == UINT32_MAX && strcmp(cmd_str, "enable") == 0){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: Port %s has no valid assigned pcap slot, cannot enable TX\n", portname);
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //process command 
    if (strcmp(cmd_str, "enable") == 0){
        atomic_store_explicit(&port_streams[global_port_index].global_start_ns, wpr_now_ns(), memory_order_release);
        atomic_fetch_add_explicit(&port_streams[global_port_index].run_gen, 1, memory_order_acq_rel);
        atomic_store_explicit(&port_entry->tx_enabled, true, memory_order_release); 
    }
    else if (strcmp(cmd_str, "disable") == 0){
        atomic_store_explicit(&port_entry->tx_enabled, false, memory_order_release); 
        atomic_fetch_add_explicit(&port_streams[global_port_index].run_gen, 1, memory_order_acq_rel);
        atomic_store_explicit(&port_streams[global_port_index].global_start_ns, wpr_now_ns(), memory_order_release);
    }
    else {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    json_object_set_new(reply_root, "status", json_integer(0));
    return 0;
}


/** 
* Set the number of active VCs (clients) for a given port stream.
* @param reply_root
*   Pointer to the json reply root object.
* @param args
*   Pointer to the json args object.
* @param thread_args
*   Pointer to the thread args structure.
* @param result
*   Pointer to integer to store result code (0=success, negative=error).    
**/
int wpr_set_port_stream_vcs(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{
    if (!reply_root || !args || !thread_args || !thread_args->global_port_list) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid arguments to wpr_set_port_stream_vcs\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    wpr_ports_t *port_list = thread_args->global_port_list;

    //extract port number from command
    json_t *jportname = json_object_get(args, "port");
    if (!jportname) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'port' argument in wpr_set_port_stream_vcs\n");
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

    //extract number of VCs from command
    json_t *jnum_vcs = json_object_get(args, "num_vcs");
    if (!jnum_vcs) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'num_vcs' argument in wpr_set_port_stream_vcs\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    uint32_t num_vcs = (uint32_t)json_integer_value(jnum_vcs);

    //set the number of active VCs for the port stream
    uint16_t global_port_index = port_entry->global_port_index;
    wpr_port_stream_global_t *port_streams = thread_args->port_stream_global_cfg;
    if(port_streams == NULL){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: port stream global config is NULL in wpr_set_port_stream_vcs\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }   
    
    atomic_store_explicit(&port_streams[global_port_index].active_clients, num_vcs, memory_order_release);

    json_object_set_new(reply_root, "status", json_integer(0));
    return 0;

}

static inline uint32_t wpr_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

/* returns 0 on success; chosen_vc_out is filled */
static int wpr_pcap_pick_vc_for_target(pcap_mbuff_slot_t *slot,
                                      wpr_target_kind_t kind,
                                      double target,
                                      uint32_t *chosen_vc_out,
                                      double *predicted_total_out)
{
    if (!slot || !chosen_vc_out || target <= 0.0){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid arguments to wpr_pcap_pick_vc_for_target\n");
        return -EINVAL;
    }

    const double margin = (slot->scaling.safety_margin > 0.0 &&
                           slot->scaling.safety_margin <= 1.0)
                            ? slot->scaling.safety_margin
                            : 1.0;

    double base = 0.0;
    switch (kind) {
    case WPR_TARGET_PPS: base = slot->scaling.base_pps_per_vc; break;
    case WPR_TARGET_BPS: base = slot->scaling.base_bps_per_vc; break;
    case WPR_TARGET_CPS: base = slot->scaling.base_cps_per_vc; break;
    default: 
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid target kind in wpr_pcap_pick_vc_for_target\n");
        return -EINVAL;
    }

    if (base <= 0.0) {
        /* template has 0 duration or 0 packets or couldn't compute */
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid base rate in wpr_pcap_pick_vc_for_target\n");
        return -ERANGE;
    }

    /* We want predicted_total = base * vc >= target*margin (or <= target depending on policy).
       For a "starting point" that reaches target, use ceil(target/(base*margin)). */
    double denom = base * margin;
    if (denom <= 0.0) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid denominator in wpr_pcap_pick_vc_for_target\n");
        return -ERANGE;
    }

    uint32_t vc = (uint32_t)ceil(target / denom);

    /* Clamp to supported range. Define max_vc_supported per port or globally. */
    uint32_t max_vc = slot->scaling.max_vc_supported ? slot->scaling.max_vc_supported : 1;
    vc = wpr_clamp_u32(vc, 1, max_vc);

    double predicted = base * (double)vc;

    /* Save debug info */
    slot->last_autotune.kind = kind;
    slot->last_autotune.target = target;
    slot->last_autotune.chosen_vc = vc;
    slot->last_autotune.predicted_total = predicted;

    *chosen_vc_out = vc;
    if (predicted_total_out) *predicted_total_out = predicted;

    return 0;
}

/** 
* Handle RPC command to set target rate for a port stream.
* @param reply_root
*   Pointer to the json reply root object.
* @param args
*   Pointer to the json args object.
* @param thread_args
*   Pointer to the thread args structure.
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid   
**/
int wpr_set_target_rate(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args){


    if (!reply_root || !args || !thread_args || !thread_args->global_port_list) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid arguments to wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    wpr_ports_t *port_list = thread_args->global_port_list;

    //extract port number from command
    json_t *jportname = json_object_get(args, "port");
    if (!jportname) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'port' argument in wpr_set_target_rate\n");
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

    //extract rate target kind from command 
    json_t *jtarget_kind = json_object_get(args, "target_kind");
    if (!jtarget_kind) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'target_kind' argument in wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //convert string to target kind enum
    const char *target_kind_str = json_string_value(jtarget_kind);
    wpr_target_kind_t target_kind;
    if (strcmp(target_kind_str, "pps") == 0){
        target_kind = WPR_TARGET_PPS;
    }
    else if (strcmp(target_kind_str, "bps") == 0){
        target_kind = WPR_TARGET_BPS;
    }
    else if (strcmp(target_kind_str, "cps") == 0){
        target_kind = WPR_TARGET_CPS;
    }
    else {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid 'target_kind' argument in wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //get target value
    json_t *jtarget_value = json_object_get(args, "target_value");
    if (!jtarget_value) {
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: missing 'target_value' argument in wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    double target_value = json_real_value(jtarget_value);
    if (target_value <= 0.0){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: invalid 'target_value' argument in wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }   

    //get global port stream config for this port
    uint16_t global_port_index = port_entry->global_port_index;
    wpr_port_stream_global_t *port_streams = thread_args->port_stream_global_cfg;
    if(port_streams == NULL){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: port stream global config is NULL in wpr_set_target_rate\n");
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //get slot assigned to this port stream 
    uint32_t slot_id = atomic_load_explicit(&port_streams[global_port_index].slot_id, memory_order_acquire);
    if (slot_id == UINT32_MAX){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: Port %s has no valid assigned pcap slot, cannot set target rate\n", portname);
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    pcap_mbuff_slot_t *slot = atomic_load_explicit(&thread_args->pcap_storage->slots[slot_id], memory_order_acquire);;
    if (slot == NULL){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: Port %s assigned pcap slot %u is not loaded, cannot set target rate\n", portname, slot_id);
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //pick number of VCs needed to meet target rate
    uint32_t chosen_vc = 0;
    double predicted_total = 0.0;
    int rc = wpr_pcap_pick_vc_for_target(slot, target_kind, target_value, &chosen_vc, &predicted_total);
    if (rc != 0){
        WPR_LOG(WPR_LOG_RPC, RTE_LOG_ERR, "Error: could not pick VCs for target rate on port %s\n", portname);
        json_object_set_new(reply_root, "status", json_integer(rc));
        return rc;
    }

    //set the number of active VCs for the port stream
    atomic_store_explicit(&port_streams[global_port_index].active_clients, chosen_vc, memory_order_release);

    //return result
    json_object_set_new(reply_root, "status", json_integer(0));
    json_object_set_new(reply_root, "chosen_vcs", json_integer(chosen_vc));
    json_object_set_new(reply_root, "predicted_total", json_real(predicted_total));

    return 0; 
}