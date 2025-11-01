/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ports.h 
Description: header file for dpdk port init functions

*/

#ifndef PORTS_H
#define PORTS_H

int ps_port_init(uint16_t port, struct rte_mempool *mbuf_pool, unsigned int core_count );

#endif