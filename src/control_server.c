/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: control_server.c
Description: Primary entry point and support functionality for a light weight socket based control server 
for managing the Pcap Replay dataplane. The control server is launched as a standard pthread (not a dpdk thread)
and bound to the management core so it won't impact datapath performance. 

The control server monitors for requests sent via TCP on a port specified at thread launch time as one of the thread 
arguments. The server operates with json formatted strings as both the command and response payload format. 

A majority of the support functions are statically defined, only used by the main server thread. 

All functions / commmands have a similar flow, a json command is received over the socket in the format {"cmd": "cmdstr"}. basic sanity 
checks are performed (not extensive, this isn't prod code). Commands are dispatched to a handler that selects a specific "return_x" function 
which performs the required command and also formats the return json response. Since responses are just json strings, the specific format differs
depending on the specific command / function. 

*/

#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <stdio.h> 
#include <unistd.h>

#include "app_defines.h"
#include "control.h"
#include "stats.h"
#include "pcap_loader.h"
#include "flowtable.h"


/* Helper function - build a 5 tuple key struct based on parameters pased from a json command */
static int get_fivetup_key(json_t *cmd_args, struct flow5 *key){
    //get src ip for the key  
    struct in_addr  v4_src;
    struct in6_addr v6_src;
    const char *srcip_s = json_string_value(json_object_get(cmd_args, "src_ip"));    
    if (inet_pton(AF_INET, srcip_s, &v4_src) == 1) {
        key->family = FT_IPV4;
        memset(key->src, 0, 16);
        memcpy(&key->src[12], &v4_src, 4);   // put v4 in last 4 bytes (like v4-mapped)
    }
    else if (inet_pton(AF_INET6, srcip_s, &v6_src) == 1) {
        key->family = FT_IPV6;
        memcpy(key->src, &v6_src, 16);
    }
    else {
        return -1;
    }

    //get dst ip for the key  
    struct in_addr  v4_dst;
    struct in6_addr v6_dst;
    const char *dstip_s = json_string_value(json_object_get(cmd_args, "dst_ip"));    
    if (inet_pton(AF_INET, dstip_s, &v4_dst) == 1) {
        key->family = FT_IPV4;
        memset(key->dst, 0, 16);
        memcpy(&key->dst[12], &v4_dst, 4);   // put v4 in last 4 bytes (like v4-mapped)
    }
    else if (inet_pton(AF_INET6, dstip_s, &v6_dst) == 1) {
        key->family = FT_IPV6;
        memcpy(key->dst, &v6_dst, 16);
    }
    else {
        return -1;
    }

    //get src port if present
    int src_port = json_integer_value(json_object_get(cmd_args, "src_port"));    
    if (0 <= src_port && src_port <= 65535){
        key->src_port = rte_cpu_to_be_16(src_port);
    }
    else{ 
        return -3;
    } 

    //get dst port if present
    int dst_port = json_integer_value(json_object_get(cmd_args, "dst_port"));    
    if (0 <= dst_port && dst_port <= 65535){
        key->dst_port = rte_cpu_to_be_16(dst_port);
    }
    else {
        return -4;
    }

    //get proto if present
    int proto = json_integer_value(json_object_get(cmd_args, "proto"));    
    if (0 <= proto && proto <= 255){
        key->proto = proto;
    }
    else{ 
        return -5;
    } 

    return 0;
}

/* Helper function - build a flowtable action based on a json command input */
static int format_action(json_t *cmd_args, struct ft_action *new_action){
    int rc = 0;

    //get action kind field
    enum ft_action_kind kind = (enum ft_action_kind)json_integer_value(json_object_get(cmd_args, "kind"));
    new_action->kind = kind; 
    new_action->default_rule = false;
    new_action->src_mac_valid = false;
    new_action->dst_mac_valid = false;
    new_action->src_ip_valid = false;
    new_action->dst_ip_valid = false;
    new_action->sport_valid = false;
    new_action->dport_valid = false;


    //get src mac if present 
    struct rte_ether_addr src_mac = {0};
    const char *srcmac_s = json_string_value(json_object_get(cmd_args, "a_src_mac"));
    if (rte_ether_unformat_addr(srcmac_s, &src_mac) == 0) {
        new_action->new_src_mac = src_mac; 
        new_action->src_mac_valid = true;
    }
    else {
        rte_ether_unformat_addr("0:0:0:0:0:0", &new_action->new_src_mac);
    }   

    //get src dst mac if present 
    struct rte_ether_addr dst_mac = {0};
    const char *dstmac_s = json_string_value(json_object_get(cmd_args, "a_dst_mac"));
    if (rte_ether_unformat_addr(dstmac_s, &dst_mac) == 0) {
        new_action->new_dst_mac = dst_mac; 
        new_action->dst_mac_valid = true;
    }
    else {
        rte_ether_unformat_addr("0:0:0:0:0:0", &new_action->new_dst_mac);
    }  

    //get src ip if preset 
    struct in_addr src_addr; 
    const char *srcip_s = json_string_value(json_object_get(cmd_args, "a_src_ip"));    
    if (inet_pton(AF_INET, srcip_s, &src_addr) == 1) {
        new_action->new_src_ip_subnet = src_addr.s_addr;
        new_action->src_ip_valid = true;
    }
    else {
        new_action->new_src_ip_subnet = 0;
    }

    //get dst ip if preset 
    struct in_addr dst_addr; 
    const char *dstip_s = json_string_value(json_object_get(cmd_args, "a_dst_ip"));    
    if (inet_pton(AF_INET, dstip_s, &dst_addr) == 1) {
        new_action->new_dst_ip_subnet = dst_addr.s_addr;
        new_action->dst_ip_valid = true;
    }
    else {
        new_action->new_dst_ip_subnet = 0;
    }

    //get src port if present
    int src_port = json_integer_value(json_object_get(cmd_args, "a_src_port"));    
    if (0 <= src_port && src_port <= 65535){
        new_action->new_sport = rte_cpu_to_be_16(src_port);
        new_action->sport_valid = true;
    } 

    //get dst port if present
    int dst_port = json_integer_value(json_object_get(cmd_args, "a_dst_port"));    
    if (0 <= dst_port && dst_port <= 65535){
        new_action->new_dport = rte_cpu_to_be_16(dst_port);
        new_action->dport_valid = true;
    } 

    return rc;
}

/* Helper function - check the status of the flowtable controller*/
static int check_ftcontroller_status(struct pthread_args *thread_args, int *result){
    int done = 0;
    
    int gotlock = pthread_mutex_trylock(&thread_args->ft_controller->lock);
    if (gotlock == 0){
        if (!thread_args->ft_controller->busy && thread_args->ft_controller->command == FT_CMD_NONE) {
            // worker finished last command
            *result = thread_args->ft_controller->result;
            done = 1;
        }
        pthread_mutex_unlock(&thread_args->ft_controller->lock);
    }
    return done;
}

/* build a flow table action and key from json command and add it to the flow table */
static int return_add_flowaction(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int rc = 0; 
    
    //get new action struct
    struct ft_action new_act = {0};
    rc = format_action(cmd_args, &new_act);
    if (rc < 0){
        printf("Failed to build action struct: %d\n", rc);
        goto end;        
    }

    //build key 
    struct flow5 key = {0};
    rc = get_fivetup_key(cmd_args, &key);
    if (rc < 0){
        printf("Failed to create key 5tuple: %d\n", rc);
        goto end;
    }

    /*
    printf("srcip: 0x");
    for (int i =0;i<16;i++){
        printf("%x",key.src[i]);
    }
    printf("\ndstip: 0x");
    for (int i =0;i<16;i++){
        printf("%x",key.dst[i]);
    }   
    printf("\nsrcpt: 0x%lx\n", key.src_port);
    printf("dstpt: 0x%lx\n", key.dst_port);
    printf("proto: 0x%lx\n", key.proto);
    */

    //get lock 
    pthread_mutex_lock(&thread_args->ft_controller->lock);
    
    //update command args 
    thread_args->ft_controller->new_action = &new_act;
    thread_args->ft_controller->key = &key;

    //signal loader thread
    thread_args->ft_controller->command = FT_CMD_ADD_ENTRY;
    pthread_mutex_unlock(&thread_args->ft_controller->lock);


    //wait for action to compelte to complete
    while(check_ftcontroller_status(thread_args,&rc) == 0){
        sched_yield();
    }

end: 
    json_object_set_new(root,"status",json_integer(rc)); 
    return 0; 
}

/* build a flow table action and key from json command and modify an existing entry in the flow table */
static int return_mod_flowaction(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int rc = 0; 
    
    //get new action struct
    struct ft_action new_act = {0};
    rc = format_action(cmd_args, &new_act);
    if (rc < 0){
        printf("Failed to build action struct: %d\n", rc);
        goto end;        
    }

    //build key 
    struct flow5 key = {0};
    rc = get_fivetup_key(cmd_args, &key);
    if (rc < 0){
        printf("Failed to create key 5tuple: %d\n", rc);
        goto end;
    }

    //get lock 
    pthread_mutex_lock(&thread_args->ft_controller->lock);
    
    //update command args 
    thread_args->ft_controller->new_action = &new_act;
    thread_args->ft_controller->key = &key;
    thread_args->ft_controller->opt_old_action =NULL;

    //signal loader thread
    thread_args->ft_controller->command = FT_CMD_MOD_ENTRY;
    pthread_mutex_unlock(&thread_args->ft_controller->lock);


    //wait for action to compelte to complete
    while(check_ftcontroller_status(thread_args,&rc) == 0){
        sched_yield();
    }

end: 
    json_object_set_new(root,"status",json_integer(rc)); 
    return 0; 
}

/* build a flow table action and key from json command and modify an existing entry in the flow table */
static int return_append_flowaction(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int rc = 0; 
    
    //get new action struct
    struct ft_action new_act = {0};
    rc = format_action(cmd_args, &new_act);
    if (rc < 0){
        printf("Failed to build action struct: %d\n", rc);
        goto end;        
    }

    //build key 
    struct flow5 key = {0};
    rc = get_fivetup_key(cmd_args, &key);
    if (rc < 0){
        printf("Failed to create key 5tuple: %d\n", rc);
        goto end;
    }

    //get lock 
    pthread_mutex_lock(&thread_args->ft_controller->lock);
    
    //update command args 
    thread_args->ft_controller->new_action = &new_act;
    thread_args->ft_controller->key = &key;
    thread_args->ft_controller->opt_old_action =NULL;

    //signal loader thread
    thread_args->ft_controller->command = FT_CMD_APP_ENTRY;
    pthread_mutex_unlock(&thread_args->ft_controller->lock);


    //wait for action to compelte to complete
    while(check_ftcontroller_status(thread_args,&rc) == 0){
        sched_yield();
    }

end: 
    json_object_set_new(root,"status",json_integer(rc)); 
    return 0; 
}

/* delete an existing entry in the flowtable based on key from the json command */
static int return_del_flowaction(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int rc = 0; 
    
    //build key 
    struct flow5 key = {0};
    rc = get_fivetup_key(cmd_args, &key);
    if (rc < 0){
        printf("Failed to create key 5tuple: %d\n", rc);
        goto end;
    }

    //get lock 
    pthread_mutex_lock(&thread_args->ft_controller->lock);
    
    //update command args 
    thread_args->ft_controller->new_action = NULL;
    thread_args->ft_controller->key = &key;

    //signal loader thread
    thread_args->ft_controller->command = FT_CMD_DEL_ENTRY;
    pthread_mutex_unlock(&thread_args->ft_controller->lock);


    //wait for action to compelte to complete
    while(check_ftcontroller_status(thread_args,&rc) == 0){
        sched_yield();
    }

end: 
    json_object_set_new(root,"status",json_integer(rc)); 
    return 0; 
}

/* Return json formated global state information. This was the first return function I wrote and was for initial testing purposes. Will extend this
   to include more port state in the future */
static int return_virt_channels(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int portno              = (int)json_integer_value(json_object_get(cmd_args, "portno"));
    int num_virt_channels   = (int)json_integer_value(json_object_get(cmd_args, "virt_channels"));

    printf("configuring port %d for %d virtual channels\n",portno,num_virt_channels);

    thread_args->global_state->virt_channels_per_port[portno] = num_virt_channels;
    
    json_object_set_new(root,"status",json_integer(0)); 
    return 0; 
}

/* return a json array of the current tx/port pcap slot assignments 
packet transmission is controlled by assigning each tx core and port combo a specific pcap slot id. 
pcaps are first loaded into a dynamic storage array, then users can assign a pcaps slot ID to a specific 
tx core and port combo. 

The reason for per tx core pcap slots is so pre-parsed (flow seprated) pcaps can be loaded per core, maximizing the overall 
tx pps rate of the traffic generator. */
static int return_slot_assign(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int pcap_slot   = (int)json_integer_value(json_object_get(cmd_args, "pcap_slotid"));
    int portno      = (int)json_integer_value(json_object_get(cmd_args, "portno"));
    int tx_core_id  = (int)json_integer_value(json_object_get(cmd_args, "coreid"));
    int mode        = (int)json_integer_value(json_object_get(cmd_args, "mode"));
    
    pcap_replay_t opmode;
    if(mode == 1){
        opmode = REPLAY_DIRECT;
        printf("replay direct\n");
    }
    else if (mode == 2) {
        opmode = DYN_EXPAND;
        printf("dynamic expansions\n");
    }
    else{
        printf("invalid operating mode\n");
        json_object_set_new(root,"status",json_integer(-1)); 
        return -1; 
    }    

    //check if pcap slotid is valid
    if (pcap_slot >= 0 && pcap_slot < thread_args->global_state->pcap_storage_t->count){
        
        printf("assigning pcap_slot %d to portno %d txcore %d slot\n", pcap_slot,portno,tx_core_id);
        thread_args->global_state->pcap_storage_t->slot_assignments[portno][tx_core_id] = pcap_slot;
        thread_args->global_state->pcap_storage_t->slots[pcap_slot].mode = opmode;
    }
    else{
        printf("pcap slot %d is out of valid range\n", pcap_slot);
        json_object_set_new(root,"status",json_integer(-1)); 
        return -1; 
    }

    json_object_set_new(root,"status",json_integer(0)); 
    return 0; 
}

/* enable transmission on a specified port. if the port argument is "-1" transmission is enabled on all configured ports. 
else the port number provided is checked to see if all required port+tx core slots have already been assigned a valid pcap id. 
if not it will return failure, else it will set the relivant port enable flags. 

buffer threads look for this flag to start consuming and populating tx double buffer arrays. 
*/
static int return_port_enable(json_t *root, struct pthread_args *thread_args, json_t *cmd_args, int onoff){
    //extract port number from command
    int portno   = (int)json_integer_value(json_object_get(cmd_args, "portno"));

    //enable all ports
    if(portno == -1){
        for (int i=0; i<thread_args->global_state->ports_configured;i++){

            //check if port slot has a pcap id assigned 
            for (int j=0; j< thread_args->global_state->num_tx_cores;j++){
                if (thread_args->global_state->pcap_storage_t->slot_assignments[i][j] == -1){
                    
                    printf("error, port number %d , txcore %d does not have a pcap slot assigned\n",i,j);
                    json_object_set_new(root,"status",json_integer(-1)); 
                    return -1;

                }
            }
            
            //enable port
            thread_args->global_state->port_enable[i] = onoff;
        }
    } 
    //enable a specific port
    else if (portno >=0 && portno < thread_args->global_state->ports_configured){
        //check if port slot has a pcap id assigned 
        for (int j=0; j< thread_args->global_state->num_tx_cores;j++){
            if (thread_args->global_state->pcap_storage_t->slot_assignments[portno][j] == -1){
                printf("error, port number %d , tx core %d slot does not have a pcap slot assigned\n",portno,j);
                json_object_set_new(root,"status",json_integer(-1)); 
                return -1; 
            }
        }
            
        //enable port
        printf("portno: %d, onoff: %d\n", portno,onoff);
        thread_args->global_state->port_enable[portno] = onoff;     
    }
    else{
        printf("invalid port number provided %d\n", portno);
        json_object_set_new(root,"status",json_integer(-1)); 
        return -1;
    }
 
    json_object_set_new(root,"status",json_integer(0)); 
    return 0; 
}

/* Return a json mapping of Tx Core to buffer filler core ID s */
static int return_list_coremap(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    int num_tx_cores = thread_args->global_state->num_tx_cores;

    for(int i=0; i<num_tx_cores;i++){

        json_t *buff_arr = json_array();
        //iterate over tx threads buffer cores 
        for (int j =0; j < thread_args->global_state->tx_buff_core_mapping[i].total_fillers;j++){
            json_array_append_new(buff_arr,json_integer(thread_args->global_state->tx_buff_core_mapping[i].filler_cores[j]));
        }

        char txcore[32];
        sprintf(txcore,"tx_core_%d", thread_args->global_state->tx_buff_core_mapping[i].tx_core);
        json_object_set_new(root,txcore,buff_arr);
    }

    return 0; 
}


/* Return a json list of all pcaps loaded into memory currently. Returns the following information for each active pcap storage slot
- slot id 
- pcap name 
- number of mbuffs in the slot array
- which tx core it's assigned to 
*/
static int return_pcap_list(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    
    int num_pcaps = thread_args->global_state->pcap_storage_t->count;

    json_object_set_new(root,"num_pcaps",json_integer(num_pcaps));
    json_t *arr = json_array();
    for(int i=0; i<num_pcaps;i++){
        json_t *pcap_info = json_object();
        char *pcapname  = thread_args->global_state->pcap_storage_t->slots[i].pcap_name;
        int numpackets  = thread_args->global_state->pcap_storage_t->slots[i].numpackets;
        uint64_t start_ns = thread_args->global_state->pcap_storage_t->slots[i].start_ns;
        uint64_t end_ns = thread_args->global_state->pcap_storage_t->slots[i].end_ns;
        uint64_t delta_ns = thread_args->global_state->pcap_storage_t->slots[i].delta_ns;
        uint64_t size_bytes = thread_args->global_state->pcap_storage_t->slots[i].size_in_bytes;

        json_object_set_new(pcap_info,"slotid",json_integer(i));
        json_object_set_new(pcap_info,"pcap_name",json_string(pcapname));
        json_object_set_new(pcap_info,"pcap_packets",json_integer(numpackets));
        json_object_set_new(pcap_info,"first_ns",json_integer(start_ns));
        json_object_set_new(pcap_info,"last_ns",json_integer(end_ns));
        json_object_set_new(pcap_info,"delta_ns",json_integer(delta_ns));
        json_object_set_new(pcap_info,"size_in_bytes",json_integer(size_bytes));

        json_array_append_new(arr,pcap_info);

    }

    json_object_set_new(root,"loaded_pcaps",arr);
    return 0;
}

/* 
The next two functions (check_pcap_status) and (return_pcap_loader) are responsible for taking a pcapfile path and loading it into the
Pcap Replay pcap storage memory.  
*/

/* check for pcap loading complete - polls pcap thread control structure 
   returns 0 if busy and 1 if done. slot ID loaded and result (error) returned in pointers 
*/
static int check_pcap_status(struct pthread_args *thread_args, int *result, unsigned int *slot){
    int done = 0;
    
    pthread_mutex_lock(&thread_args->pcap_controller->lock);
    if (!thread_args->pcap_controller->busy && thread_args->pcap_controller->command == CMD_NONE) {
        // worker finished last command
        *result = thread_args->pcap_controller->result;
        *slot   = thread_args->pcap_controller->latest_slotid;
        done = 1;
    }
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);
    return done;
}

/* Primary pcap load command handler. This function takes a filename and a assigned tx core ID 
   from the command args json struct and uses the information to kick the pcap_loader pthread. 
   
   The pcap_loader pthread is started at lanch time (launched from the main DPDk thread) and
   sits in a poll loop waiting for commands to be issued. Pcap loader command and status are 
   relayed using a shared memory pcap control struct that is accessed via the thread args struct. 

   access to the pcap loader control struct is guarded with standard pthread muxtex locks. 

   after completing the load operation, the function formats a response json string into the root json 
   pointer provided by the dispatch function (this is the return string). 

   note, this function both kicks and then waits for the pcap_loader thread to complete the load operation, 
   polling on loader complete (above function). This negates the use of a separate loader thread. I designed it this way
   so in the future if I want the loader thread to do more work per pcap (like TSO aggregation), the logic can be changed to not 
   block the control_server thread while loading / processing pcaps.

*/
static int return_pcap_loader(json_t *root, struct pthread_args *thread_args, json_t *cmd_args){
    
    //extract filename from command
    const char *filename             = json_string_value(json_object_get(cmd_args, "filename"));

    //get pcap thread lock
    pthread_mutex_lock(&thread_args->pcap_controller->lock);

    //copy filename into shared struct 
    snprintf(thread_args->pcap_controller->filename, sizeof(thread_args->pcap_controller->filename), "%s", filename);

    //signal loader thread
    thread_args->pcap_controller->command = CMD_LOAD_PCAP;
    pthread_cond_signal(&thread_args->pcap_controller->cond);
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);

    //wait for load to complete , will change this later 
    int pcap_error = 0;
    unsigned int slot = 0;
    while(check_pcap_status(thread_args,&pcap_error,&slot) == 0){
        usleep(10*1000);
    }

    int numpackets  = thread_args->global_state->pcap_storage_t->slots[slot].numpackets;

    //format result
    json_object_set_new(root,"status",json_integer(pcap_error));
    json_object_set_new(root,"slot",json_integer(slot));
    json_object_set_new(root,"num_packets",json_integer(numpackets));

    //print pcap storage stats 
    int count = thread_args->global_state->pcap_storage_t->count;
    printf("pcap stored in slot: %d\n", count);

    //read all slots 
    for (int i = 0; i < count; i++){
        char *pcapname  = thread_args->global_state->pcap_storage_t->slots[i].pcap_name;
        int pcap_mbufs  = thread_args->global_state->pcap_storage_t->slots[i].numpackets;

        printf("Slot %d - File Loaded: %s, NumPackets: %d\n",i,pcapname,pcap_mbufs);
    }

    return 0; 
}

/* jsonize and return all configured memory pool stats. memory pool stats are periodically collected / computed from a separate statistics pthread  
this function just grabs the latest copy of each mempool stats struct and returns it in json format. There is always N tx cores + 1 memory pools, 
one for each port and then the master / template memory pool. */
static int return_mem_stats(json_t *root, struct pthread_args *thread_args){
    pthread_mutex_lock(&(thread_args->global_stats->mem_stats->lock));

    json_t *arr = json_array();
    json_t *mem_info = json_object();
    char name[32];
    sprintf(name,"template_pcap_pool");

    json_object_set_new(mem_info, "pool_name", json_string(name));
    json_object_set_new(mem_info, "mem_available", json_integer(thread_args->global_stats->mem_stats->mstats[0].available));
    json_object_set_new(mem_info, "mem_used", json_integer(thread_args->global_stats->mem_stats->mstats[0].used));
    json_object_set_new(mem_info, "mem_total", json_integer(thread_args->global_stats->mem_stats->mstats[0].total));
    json_array_append_new(arr,mem_info);

    for(int i=0;i<thread_args->global_state->num_tx_cores;i++){
        json_t *mem_info = json_object();
        char name[32];
        sprintf(name,"tx_core_%d_clonepool",i);

        json_object_set_new(mem_info, "pool_name", json_string(name));
        json_object_set_new(mem_info, "mem_available", json_integer(thread_args->global_stats->mem_stats->mstats[i+1].available));
        json_object_set_new(mem_info, "mem_used", json_integer(thread_args->global_stats->mem_stats->mstats[i+1].used));
        json_object_set_new(mem_info, "mem_total", json_integer(thread_args->global_stats->mem_stats->mstats[i+1].total));
        json_array_append_new(arr,mem_info);        
    }

    json_object_set_new(root,"mempool_info",arr);
    pthread_mutex_unlock(&(thread_args->global_stats->mem_stats->lock));
    return 0;
}

/* jsonize and return all configured port stats. Port stats are periodically collected / computed from a separate statistics pthread  
this function just grabs the latest copy of each port stats struct. The stats thread reads DPDK xstats per port and also computes rates based on 
a preconfigured poll frequency. 
*/
static int return_port_stats(json_t *root, struct pthread_args *thread_args){
    //claim portstats lock 
    pthread_mutex_lock(&(thread_args->global_stats->port_stats->lock));

    char portname[30];
    //iterate across ports and grab latest stats, format into json struct
    for(int i=0; i<thread_args->global_stats->port_stats->num_ports; i++){
        sprintf(portname, "port%d",i);
        json_t *portstats = json_object();
        
        //iterate over all xstats for the port
        for (int j = 0; j < thread_args->global_stats->port_stats->per_port_stats[i].n_xstats;j++){
            json_object_set_new(portstats,thread_args->global_stats->port_stats->per_port_stats[i].port_stats_names[j].name,
                json_integer(thread_args->global_stats->port_stats->per_port_stats[i].current_port_stats[j].value));
        }

        //add all rate metrics 
        for (int j = 0; j < thread_args->global_stats->port_stats->per_port_stats[i].n_xstats;j++){
            char name[128]; 
            sprintf(name, "%s_rate", thread_args->global_stats->port_stats->per_port_stats[i].port_stats_names[j].name);

            json_object_set_new(portstats,name,json_integer(thread_args->global_stats->port_stats->per_port_stats[i].rates_port_stats[j].value));
        }

        json_object_set_new(root,portname,portstats);

    }
    //release portstats lock
    pthread_mutex_unlock(&(thread_args->global_stats->port_stats->lock));    

    return 0;
}

/* Return json formated global state information. This was the first return function I wrote and was for initial testing purposes. Will extend this
   to include more port state in the future */
static int return_state(json_t *root, struct pthread_args *thread_args){
    
    /* Collect fields for shared state struct */
    //get access to state lock 
    pthread_mutex_lock(&(thread_args->global_state->lock));

    json_object_set_new(root, "app_initialized", json_boolean(thread_args->global_state->app_initialized));
    json_object_set_new(root, "num_ports_configured", json_integer(thread_args->global_state->ports_configured));

    json_t *arr = json_array();

    for (int i=0;i<thread_args->global_state->ports_configured;i++){
        json_array_append_new(arr,json_integer(thread_args->global_state->port_status[i]));
    }
    json_object_set_new(root, "port_status", arr);

    //release lock when done 
    pthread_mutex_unlock(&(thread_args->global_state->lock));

    return 0; 
}

/* Command Handler Function - processes received json formatted commands 
   processes commands, and returns responses */
static void handle_command(const char *msg, int fd, struct pthread_args *thread_args) {
    
    /* Parse the command and confirm is a valid json command if not return error*/
    json_error_t error;
    json_t *root = json_loads(msg, 0, &error);
    if (!root) {
        json_t *err = json_pack("{s:s}", "error", "invalid JSON");
        char *reply = json_dumps(err, 0);
        send(fd, reply, strlen(reply), 0);
        free(reply);
        json_decref(err);
        return;
    }

    /* Extract command as string, keep args as json for flexible parsing per command*/
    const char *cmd   = json_string_value(json_object_get(root, "cmd"));
    json_t *sock_args = json_object_get(root, "args");
    
    json_t *reply = json_object();
    
    /* main logic for selecting how to process a command, this is where we add new hooks for future commands */

    /* If command string is not present, return error message */
    if (!cmd) {
        reply = json_pack("{s:s}", "error", "missing cmd");

    /* Ping Command */
    } else if (strcmp(cmd, "ping") == 0) {
        reply = json_pack("{s:s}", "status", "pong");

    /* fetch all port stats */    
    } else if (strcmp(cmd, "port_stats") == 0) {
        return_port_stats(reply, thread_args);

    } else if (strcmp(cmd, "mem_stats") == 0) {
        return_mem_stats(reply, thread_args);
    
    /* fetch system status information */
    } else if (strcmp(cmd, "status") == 0) {
        return_state(reply, thread_args);

    /* Enable transmission on a port */
    } else if (strcmp(cmd, "tx_enable") == 0) {
        return_port_enable(reply, thread_args, sock_args,1);

    /* Disable transmission on a port */
    } else if (strcmp(cmd, "tx_disable") == 0) {
        return_port_enable(reply, thread_args, sock_args,0);

    /* process add flowtable action instruction */
    }else if (strcmp(cmd, "add_flowaction") == 0){
        return_add_flowaction(reply, thread_args, sock_args);

    /* process modify flowtable action instruction */
    }else if (strcmp(cmd, "mod_flowaction") == 0){
        return_mod_flowaction(reply, thread_args, sock_args);

    /* process modify flowtable action instruction */
    }else if (strcmp(cmd, "del_flowaction") == 0){
        return_del_flowaction(reply, thread_args, sock_args);

   }else if (strcmp(cmd, "append_flowaction") == 0){
        return_append_flowaction(reply, thread_args, sock_args);

    /* process pcap load instruction */
    }else if (strcmp(cmd, "load_pcap") == 0){
        return_pcap_loader(reply, thread_args, sock_args);

    }else if (strcmp(cmd, "slot_assign") == 0){
        return_slot_assign(reply, thread_args, sock_args);

    }else if (strcmp(cmd, "virt_channels_enabled") == 0){
        return_virt_channels(reply, thread_args, sock_args);

    /* list pcaps loaded into memory */
    }else if (strcmp(cmd, "list_pcaps") == 0){
        return_pcap_list(reply, thread_args, sock_args);

    /* get tx to buffer core mapping*/
    }else if (strcmp(cmd, "list_coremap") == 0){
        return_list_coremap(reply, thread_args, sock_args);

    /* Unknown Command, return error message*/
    } else {
        reply = json_pack("{s:s}", "error", "unknown command");
    }

    /* Format and Send response */
    char *reply_str = json_dumps(reply, 0);
    //printf("reply string: %s\n", reply_str);
    send(fd, reply_str, strlen(reply_str), 0);
    free(reply_str);
    json_decref(reply);
    json_decref(root);
}

/* Main control server function, listens to socket and handles commands from clients */
void *run_control_server(void *arg) {
    //reclass arg structs passed from the main thread
    struct pthread_args *thread_args = (struct pthread_args *)arg; 
    unsigned int ctl_port = *(unsigned int*)thread_args->private_args;

    /* Create an IPv4 stream oriented (TCP) socket handle */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* Configure default socket options */
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Build socket address properties, bind to CTRL_PORT and listen to local interface only 
       Assumption is DPDK server only communicates with locally running Pcap Replay python service */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctl_port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    /* Bind server to address struct */    
    if (bind(srv_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        pthread_exit((void *)-1);
    }

    /* Start listening, backlog = 4 = max 4 outstanding TCP connections */
    listen(srv_fd, 4);
    printf("\n[CTRL] Listening on port %d\n", ctl_port);

    /* Main processing loop - accept connection and use handle_command function to process*/
    char buf[MAX_SOCK_PAYLOAD];
    char command[MAX_SOCK_PAYLOAD];
    int command_len = 0; 
    
    while (1) {
        int good_command = 1; 
        int cli_fd = accept(srv_fd, NULL, NULL);
        
        /* If connection invalid don't process anything*/
        if (cli_fd < 0) continue;
        
        /* process received data */
        //printf("[CTRL] Client connected\n");
        while (good_command == 1) {
            /* Read data from client */
            ssize_t n = recv(cli_fd, buf, sizeof(buf), 0);
            // if connection fails, break 
            if (n <= 0) break;

            /* iterate through received data */
            for (int i=0; i < n ; i++) { 
                // grab next byte
                char c = buf[i];
                // if we've hit the terminator character
                if (c == '\n') {
                    //terminate command line 
                    command[command_len] = '\0';
                    
                    //if line contains valid data, process
                    if (command_len > 0) {
                        handle_command(command,cli_fd,thread_args);
                    }

                    command_len = 0; 

                /* else, keep processing received data */
                } else {
                    // if we have room in buffer, keep adding data 
                    if(command_len < sizeof(command) -1){
                        command[command_len++] = c;
                    
                    //overflow case, return malformed command error
                    } else {
                        //printf("bad command\n");
                        json_t *err = json_pack("{s:s}", "error", "Malformed Command");
                        char *reply = json_dumps(err, 0);
                        send(cli_fd, reply, strlen(reply), 0);
                        free(reply);
                        json_decref(err);
                        command_len = 0; 
                        good_command = 0; 
                        break;
                    }
                }
            }
            
            //reset buffers 
            memset(buf,0,sizeof(buf));
            memset(command,0,sizeof(command));

        }
        close(cli_fd);
        //printf("[CTRL] Client disconnected\n");
    }
    close(srv_fd);
}
