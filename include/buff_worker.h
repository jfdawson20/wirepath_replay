/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: buff_worker.h 
Description: header file for buffer worker functions and structs

*/

#ifndef BUFF_WORKER_H
#define BUFF_WORKER_H
#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <limits.h>
#include <stdatomic.h>


int buffer_worker(__rte_unused void *arg);

#endif