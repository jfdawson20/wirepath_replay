#include "ppr_stats_rpc.h"

/* --------------------------------- Stastics commands --------------------------------- */

/** 
* jsonize and return all configured memory pool stats 
* @param reply_root
*   json root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_mem_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    pthread_mutex_lock(&(thread_args->global_stats->mem_stats->lock));
    //silence unused param warnings
    (void)args;
    (void)thread_args;


    pthread_mutex_unlock(&(thread_args->global_stats->mem_stats->lock));
    return 0;
}

/** 
* jsonize and return all configured port stats
* @param reply_root
*   json reply_root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_port_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    
    // guard against null
    if (args == NULL){
        return -EINVAL;
    }
   
    //extract requested port number
    const char *portno_str = json_string_value(json_object_get(args, "portno"));
    if (portno_str == NULL){
        return -EINVAL;
    }
    int portno = atoi(portno_str);
    PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Requested port stats for port %d\n", portno);

    //calculate range if requested 
    unsigned int base_port_id = 0;
    unsigned int max_port_id = 0;
    if(portno == -1)
    {
        base_port_id = 0;
        max_port_id  = thread_args->global_port_list->num_ports;
        //if portno not specified, return stats for all ports
    }
    else if (portno < 0 || (unsigned int)portno >= thread_args->global_port_list->num_ports){
        return -EINVAL;
    }  
    else{
        base_port_id = (unsigned int)portno;
        max_port_id  = base_port_id + 1;
    }


    int rc = 0;
    char portname[30];
    //iterate across ports and grab latest stats, format into json struct
    for(unsigned int i=base_port_id; i<max_port_id; i++){
        //find entry
        ppr_port_entry_t *port_entry = ppr_find_port_by_global_index(thread_args->global_port_list, i);
        if (!port_entry) {
            PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR, "Error: Could not find port entry for port ID %u\n", i);
            continue;
        }

        //if drop port, skip 
        if(strcmp(port_entry->name, "drop_port") == 0){
            continue;
        }

        //get lock 
        pthread_mutex_lock(&(port_entry->stats.lock));

        //get stats struct pointer 
        ppr_single_port_stats_t *ps = &port_entry->stats;
        
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Processing stats for port %d\n", i);
        rc += sprintf(portname, "port%d",i);
        json_t *portstats = json_object();
        

        if(ps->port_kind == PPR_PORT_TYPE_RING){
            rc += json_object_set_new(portstats,"type",json_string("ring"));
            rc += json_object_set_new(portstats,"name",json_string(port_entry->name));
            rc += json_object_set_new(portstats,"enq_pkts",json_integer(ps->ringstats.current_ring_stats->enq_pkts));
            rc += json_object_set_new(portstats,"deq_pkts",json_integer(ps->ringstats.current_ring_stats->deq_pkts));
            rc += json_object_set_new(portstats,"drop_pkts",json_integer(ps->ringstats.current_ring_stats->drop_pkts));
            rc += json_object_set_new(portstats,"enq_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->enq_pkts));
            rc += json_object_set_new(portstats,"deq_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->deq_pkts));
            rc += json_object_set_new(portstats,"drop_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->drop_pkts));  
        } 
        else{
            //iterate over all xstats for the port
            rc += json_object_set_new(portstats,"type",json_string("NIC"));
            rc += json_object_set_new(portstats,"name",json_string(port_entry->name));
            for (int j = 0; j < ps->xstats.n_xstats;j++){
                rc += json_object_set_new(portstats,ps->xstats.port_stats_names[j].name,json_integer(ps->xstats.current_port_stats[j].value));
            }

            //add all rate metrics 
            for (int j = 0; j < ps->xstats.n_xstats;j++){
                char name[128]; 
                rc += sprintf(name, "%s_rate", ps->xstats.port_stats_names[j].name);

                rc += json_object_set_new(portstats,name,json_integer(ps->xstats.rates_port_stats[j].value));
            }
        }


        rc += json_object_set_new(reply_root,portname,portstats);
        
        //release portstats lock
        pthread_mutex_unlock(&(port_entry->stats.lock));   

    }
 

    //standardize return code
    if (rc < 0){
        return -EINVAL;
    }
    return 0;
}

