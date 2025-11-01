/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ft_manager.c 
Description: This file contains all the relavent functions and entry point for the flow manager pthread. the ft_manager runs on the service core (core 0)
along side other non-hot-path threads for control and maintance purposes. The ft_manager is for the runtime management of the flowtable used by the application, 
specifically it handles the following: 

1) Out-of-band table updates: the main control loop monitors for commands submitted by the control server thread. This is the primary method for users
to modify the contents of the flow table from other applications (e.g. python front end). The supported commands are enumerated in the ft_manager_cmd_t
enum in the header file. 

2) QSBR Reclaimation: The flow table API utilizes a quiescent state-based reclamation (QSBR) process for periodically recycling retired flow table entry
payloads (e.g. actions). Flow table updates to already established keys require swapping a new action pointer in place of the previous action pointer. however
at time of the swap, we can't be sure that one or more read threads may still be using the data pointed by the original action pointer. using QSBR, on modify or 
delete operations, the old data pointer is enqueued into a differal queue. periodically when not using flowtable data, reader threads call a function to 
indicate they are in a quescent state. The ft_manager thread periodically calls the differal queue reclaim function to bulk process retired action pointers. 

3) Flow table walk operations: any opeartion requiring periodic processing (suching as evicting expired flows, etc.) are performed as part of the ft_manager 
loop. 
*/

#include <pcap/pcap.h>             
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <rte_common.h>
#include <rte_rcu_qsbr.h>

#include "ft_manager.h"
#include "flowtable.h"
#include "app_defines.h"

/* Function to process a flow table command. The function checks the ft controller 
structure to determine if a command has been subitted. It then takes ownership of the controller lock 
and proceeds to perform the requested table operation. When complete it updates the busy and result flags and 
clears the controller lock. */
static int process_ft_command(struct pthread_args *thread_args){
        int rc = 0; 
        struct ft_manager_ctl * ctl = thread_args->ft_controller;

        // if no command to process, return
        if (ctl->command == FT_CMD_NONE){
            return 0;
        }
        else {
            //get the lock 
            pthread_mutex_lock(&ctl->lock);
            ctl->busy = true;

            //process the commman
            if (ctl->command == FT_CMD_ADD_ENTRY){
                rc = ft_add(thread_args->global_flowtable, ctl->key, ctl->new_action);
            }
            else if (ctl->command == FT_CMD_MOD_ENTRY){
                printf("mod entry\n");
                rc = ft_replace(thread_args->global_flowtable,ctl->key,ctl->new_action,ctl->opt_old_action);
            }
            else if (ctl->command == FT_CMD_DEL_ENTRY){
                printf("delete entry\n");
                rc = ft_del(thread_args->global_flowtable, ctl->key);
            }
            else if (ctl->command == FT_CMD_APP_ENTRY){
                printf("append entry\n");
                rc = ft_append(thread_args->global_flowtable,ctl->key,ctl->new_action);
            }
            else {
                printf("invalid op\n");
                rc = -1;
            }

            //clear the command
            ctl->command = FT_CMD_NONE;
            ctl->busy = false;
            ctl->result = rc; //fill  in result
            //release the lock
            pthread_mutex_unlock(&ctl->lock);
        }

    return 0;
}

/* Main entry point for flowtable manager thread. The flowtable thread runs in a loop processing tasks at a fixed frequency 
the trehad is responsible for processing any inbound flowtable commmands, running the periodic flowtable retirement qsbr functions, 
and any other periodic flowtable maintnance activitiies. */
void *run_ft_manager_thread(void *arg) {

    //setup some accessor variables for global structs
    struct pthread_args *thread_args  = (struct pthread_args *)arg;
    struct ft_manager_ctl * ctl = thread_args->ft_controller;
    struct flow_table *ft = thread_args->global_flowtable;

    //setup poll rate variables
    const uint64_t hz = rte_get_timer_hz();
    uint64_t next_tick = rte_get_timer_cycles();
    const uint64_t period = hz / 200; // 5 ms

    //we need to be a lcore to do table ops (add/mod/del, qsbr reclaimation)
    int rc = rte_thread_register(); 
    if (rc < 0){
        rte_exit(EXIT_FAILURE, "Failed to register ft_manager as a lcore thread\n");
    }

    //initialize lock when thread launches
    pthread_mutex_unlock(&ctl->lock);

    //main thread
    while (1) {
        
        //only run perodically 
        uint64_t now = rte_get_timer_cycles();
        if ((int64_t)(now - next_tick) >= 0) {
            next_tick += period;
            
            //1) check if we have a command to process, if so process it
            process_ft_command(thread_args);

            //2) run qsbr cleanup 
            unsigned int freed = 0, pending = 0, avail = 0;
            rte_rcu_qsbr_dq_reclaim(ft->dq,1,&freed, &pending, &avail);
            if(freed > 0){
                printf("freed: %d\n", freed);
            }
        }

        sched_yield();
    }

    return NULL;

}
