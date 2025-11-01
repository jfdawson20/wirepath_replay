/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ports.c 
Description: contains the code required to initialize ports for uses in a DPDK application. to configure ports we:
1) determine if the port number provided is valid 
2) get device information and capabilities 
3) Configure the port / device (number of queues, queue / ring sizes, etc.)
4) initialize port rx/tx queues 
5) enable port 
6) config promisc mode (not needed really for this app currently, but doing it for future reasons)
*/

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_common.h>

#include "app_defines.h"
#include "ports.h"

/* Port configuration function, takes a port number, mem pool, and number of tx cores and configures the port accordingly */
int ps_port_init(uint16_t port, struct rte_mempool *mbuf_pool, unsigned int core_count )
{
        struct rte_eth_conf port_conf;
        const uint16_t rx_rings = core_count, tx_rings = core_count;
        uint16_t nb_rxd = RX_RING_SIZE;
        uint16_t nb_txd = TX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        //check if port number is valid 
        if (!rte_eth_dev_is_valid_port(port))
                return -1;

        //get device info structure 
        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
                printf("Error during getting device (port %u) info: %s\n",
                                port, strerror(-retval));
                return retval;
        }

        //initialize port configuration structure 
        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

        /* Configure port properties based on device info and other factors */
        //do not use fast free mbufs since we are sending clones
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
                port_conf.txmode.offloads |=
                        RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;


        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

        /* Configure the Ethernet device. */
        //one rx/tx ring pair per worker port 
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
                return retval;

        //set rx/tx ring sizes 
        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0)
                return retval;

        /* Queue configuration */
        //Allocate and set up N RX queues per lcore. Note, for Pcap Replay we don't current use Rx processing
        //but setting it up just becase I may want to extend the app to support sequence checking in the future.
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
                if (retval < 0)
                        return retval;
        }

        //Allocate and set up N TX queues per lcore. 
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        for (q = 0; q < tx_rings; q++) {

                /* Reclaim frequently; match your burst size. */
                txconf.tx_rs_thresh   = RTE_MAX((uint16_t)32,  (uint16_t)(nb_txd / 16));
                txconf.tx_free_thresh = RTE_MAX((uint16_t)64,  (uint16_t)(nb_txd / 8));

                /* Keep constraints: tx_rs_thresh <= tx_free_thresh < nb_tx_desc-3 */
                if (txconf.tx_rs_thresh   >= nb_txd)   txconf.tx_rs_thresh = nb_txd - 8;
                if (txconf.tx_free_thresh >= nb_txd)   txconf.tx_free_thresh = nb_txd - 8;
                if (txconf.tx_rs_thresh   >  txconf.tx_free_thresh) txconf.tx_rs_thresh = txconf.tx_free_thresh;

                retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
                if (retval < 0)
                        return retval;
        }

        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
                return retval;

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        retval = rte_eth_macaddr_get(port, &addr);
        if (retval != 0) {
                printf("Error: Cannot get MAC address (port %u): %s\n",
                                port, strerror(-retval));
                return retval;
        }

        printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        port,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        if (retval != 0)
                return retval;

        return 0;
}
