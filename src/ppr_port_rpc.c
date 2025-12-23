
#include "ppr_port_rpc.h"
#include "ppr_tx_worker.h"
#include "ppr_time.h"

int ppr_cmd_get_port_list(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    //silence unused param warnings
    (void)args;
    ppr_ports_t *port_list = thread_args->global_port_list;
    json_t *portlist = json_object();

    PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n Dumping Global Port List: num_ports=%u\n", port_list->num_ports);
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        json_t *portentry = json_object();
        json_t *rx_queue_arr = json_array();
        json_t *tx_queue_arr = json_array();
        int rc = 0;

        char direction[32];
        if (port_list->ports[i].dir == PPR_PORT_RX){
            snprintf(direction, sizeof(direction), "RX");
        }
        else if (port_list->ports[i].dir == PPR_PORT_TX){
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

        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tRX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_rx_queues; q++){
            json_t *rx_queue_entry = json_object();
            rc += json_object_set_new(rx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(rx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].rx_queue_assignments[q]));
            rc += json_array_append_new(rx_queue_arr,rx_queue_entry);
            PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].rx_queue_assignments[q]);
        }
        
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
        
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tTX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_tx_queues; q++){
            json_t *tx_queue_entry = json_object();
            rc += json_object_set_new(tx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(tx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].tx_queue_assignments[q]));
            rc += json_array_append_new(tx_queue_arr,tx_queue_entry);
            PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].tx_queue_assignments[q]);
        }
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
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
int ppr_port_tx_ctl(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){

    ppr_ports_t *global_port_list = thread_args->global_port_list;

    //extract port name from command
    json_t *jportname = json_object_get(args, "port");
    if (!jportname) {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    const char *portname = json_string_value (jportname);

    //validate port entry exists
    ppr_port_entry_t *port_entry = ppr_find_port_byname(global_port_list, portname);
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
    ppr_port_stream_global_t *port_streams = thread_args->port_stream_global_cfg;
    if(port_streams == NULL){
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }
    
    //verify stream has a valid slot assignment for enable only
    uint32_t slot_id = atomic_load_explicit(&port_streams[global_port_index].slot_id, memory_order_acquire);
    if (slot_id == UINT32_MAX && strcmp(cmd_str, "enable") == 0){
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR, "Error: Port %s has no valid assigned pcap slot, cannot enable TX\n", portname);
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    //process command 
    if (strcmp(cmd_str, "enable") == 0){
        atomic_store_explicit(&port_streams[global_port_index].global_start_ns, ppr_now_ns(), memory_order_release);
        atomic_store_explicit(&port_entry->tx_enabled, true, memory_order_release); 
    }
    else if (strcmp(cmd_str, "disable") == 0){
        atomic_store_explicit(&port_entry->tx_enabled, false, memory_order_release); 
        atomic_store_explicit(&port_streams[global_port_index].global_start_ns, ppr_now_ns(), memory_order_release);
    }
    else {
        json_object_set_new(reply_root, "status", json_integer(-EINVAL));
        return -EINVAL;
    }

    json_object_set_new(reply_root, "status", json_integer(0));
    return 0;
}