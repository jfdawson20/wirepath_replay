/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ft_manager.h
Description: header file for flowtable manager thread functions

*/

#ifndef FT_MANAGER_H
#define FT_MANAGER_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "flowtable.h"

/* Enum for supported commands to ft_manager */
typedef enum {
    FT_CMD_NONE = 0,
    FT_CMD_ADD_ENTRY,
    FT_CMD_MOD_ENTRY,
    FT_CMD_DEL_ENTRY,
    FT_CMD_APP_ENTRY
} ft_manager_cmd_t;


/* Data structure for communicating with ft_manager */
struct ft_manager_ctl {
    //control and status 
    pthread_mutex_t     lock; 
    pthread_cond_t      cond; 
    ft_manager_cmd_t    command; 
    int                 result; 
    bool                busy;
    
    //data transfer
    struct flow5 *key;
    struct ft_action *new_action;
    struct ft_action **opt_old_action;

};

void *run_ft_manager_thread(void *arg);

#endif
