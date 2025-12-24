/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_ports.c 
Description: the ports API is responsible for managing all ports in the system, including physical NIC ports and ring based ports. it includes logic for 
building and maintaining a global port list structure that contains all ports in the system along with their parameters. it also includes logic for 
initializing physical ports via DPDK and setting up ring based ports. the ports API also provides a simple dynamic array implementation for managing the list 
of ports.

During initialization, the ports API is used to create the global port list based on the application configuration, and assign ports and queues to worker cores.
the global port list is then passed to other subsystems such as the egress table and packet I/O API to allow them to interact with ports in a uniform manner. The
heart of the ports API is the wpr_port_entry_t struct which contains all relevant information about a port, including its type (physical or ring), port ID, queue assignments,
and statistics. The ports API also includes functions for adding, deleting, and finding ports in the global port list, as well as printing the port list for 
debugging purposes.

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h> 
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_dev.h>
#include <rte_bus.h>
#include <pthread.h>
#include <rte_malloc.h>


#include "wpr_app_defines.h"
#include "wpr_ports.h"
#include "wpr_log.h"

wpr_ring_stats_name_t WPR_PORT_RINGSTAT_NAMES[] = {
    {"enq_pkts"},
    {"deq_pkts"},
    {"drop_pkts"},
};
            
/* ------------------------------------ Simple dynamic array API for ports ----------------------------- */

/**
* Initialize a port list.
* @param port_list
*   Pointer to the port list structure.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_port_list_init(wpr_ports_t **port_list_ptr) {
    if (*port_list_ptr != NULL){
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "Port list pointer must be NULL on init\n");
        return -EINVAL;
    }

    *port_list_ptr = (wpr_ports_t *)calloc(1,sizeof(wpr_ports_t));
    if (!*port_list_ptr) {
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "Failed to allocate memory for port list\n");
        return -ENOMEM; // allocation failed
    }

    wpr_ports_t *port_list = *port_list_ptr;
    port_list->num_ports = 0;
    port_list->port_capacity = 4; // initial capacity
    port_list->ports = (wpr_port_entry_t *)malloc(sizeof(wpr_port_entry_t) * port_list->port_capacity);
    return 0;
}

/** 
* Free resources associated with a port list structure.
* @param port_list
*   Pointer to the port list structure.
* @return
*   0 on success, negative errno on failure.
**/
void wpr_port_list_free(wpr_ports_t *list)
{
    if (!list) return;

    for (unsigned i = 0; i < list->num_ports; i++) {
        wpr_port_entry_t *p = &list->ports[i];
        wpr_free_port(p);
    }

    free(list->ports);
    free(list);
}

/**
* Add a port to the port list.
* @param port_list
*   Pointer to the port list structure.
* @param name
*   Name of the port.
* @param port_id
*   Port ID for the port.
* @param is_remote
*   True if the port is remote, false if local.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_portlist_add(wpr_ports_t *port_list, const char * name, uint16_t port_id, 
    bool is_external,wpr_port_kind_t kind, uint16_t total_rx_queues, uint16_t total_tx_queues, wpr_port_dir_t dir) {
    
    // Resize ports array if needed
    if (port_list->num_ports >= port_list->port_capacity) {
        port_list->port_capacity *= 2;
        port_list->ports = realloc(port_list->ports, sizeof(wpr_port_entry_t) * port_list->port_capacity);
        if (!port_list->ports) {
            return -ENOMEM; // realloc failed
        }
    }

    //set port parameters

    port_list->ports[port_list->num_ports].parent_port_list = port_list;

    //create arrays to hold what core owns which queue ids
    port_list->ports[port_list->num_ports].rx_queue_assignments = calloc(total_rx_queues, sizeof(uint16_t));
    if(port_list->ports[port_list->num_ports].rx_queue_assignments == NULL){
        return -ENOMEM;
    }

    port_list->ports[port_list->num_ports].tx_queue_assignments = calloc(total_tx_queues, sizeof(uint16_t));
    if(port_list->ports[port_list->num_ports].tx_queue_assignments == NULL){
        free(port_list->ports[port_list->num_ports].rx_queue_assignments);
        return -ENOMEM;
    }

    for (int i=0;i< total_rx_queues;i++){
        port_list->ports[port_list->num_ports].rx_queue_assignments[i] = UINT16_MAX; //initialize to invalid
    }
    for (int i=0;i< total_tx_queues;i++){
        port_list->ports[port_list->num_ports].tx_queue_assignments[i] = UINT16_MAX; //initialize to invalid
    }

    atomic_store_explicit(&port_list->ports[port_list->num_ports].tx_enabled, false, memory_order_release);

    port_list->ports[port_list->num_ports].name             = strdup(name);
    port_list->ports[port_list->num_ports].port_id          = port_id;
    port_list->ports[port_list->num_ports].total_rx_queues  = total_rx_queues;
    port_list->ports[port_list->num_ports].total_tx_queues  = total_tx_queues;
    port_list->ports[port_list->num_ports].dir              = dir;
    port_list->ports[port_list->num_ports].is_external      = is_external;
    port_list->ports[port_list->num_ports].kind             = kind; 
    port_list->ports[port_list->num_ports].global_port_index = port_list->num_ports;

    //state variables 
    if(kind == WPR_PORT_TYPE_ETHQ){
        port_list->ports[port_list->num_ports].admin_state   = false; 
        port_list->ports[port_list->num_ports].is_up         = false; 
    }
    else {
        port_list->ports[port_list->num_ports].admin_state   = true;
        port_list->ports[port_list->num_ports].is_up         = true;
    }

    port_list->ports[port_list->num_ports].speed_mbps        = 0;
    port_list->ports[port_list->num_ports].autoneg           = false;

    atomic_store_explicit(&port_list->ports[port_list->num_ports].is_reconfiguring, false, memory_order_release);
    port_list->ports[port_list->num_ports].cfg_link_speed_mbps = 0;
    port_list->ports[port_list->num_ports].cfg_autoneg       = false;
    port_list->ports[port_list->num_ports].cfg_duplex_full   = false;
    port_list->ports[port_list->num_ports].cfg_adv_speed_mask = 0;

    port_list->num_ports++;

    return 0;
}

/**
* Free resources associated with a load balancing node.
* @param node
*   Pointer to the load balancing node structure.   
**/
int wpr_free_port(wpr_port_entry_t *port) {
    
    free(port->rx_queue_assignments);
    free(port->tx_queue_assignments);
    //port stats allocates memory, make sure to free it
    wpr_port_stats_free(port);
    
    if (port->name) {
        free((void *)port->name);
    }
    return 0;
}

/**
* Delete a node from a load balancing group by name.
* @param g
*   Pointer to the load balancing group structure.
* @param node_name
*   Name of the load balancing node to delete.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_portlist_delete_byname(wpr_ports_t *port_list, const char *port_name) {
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        if (strcmp(port_list->ports[i].name, port_name) == 0) {
            wpr_free_port(&port_list->ports[i]);

            // Shift remaining ports down
            memmove(&port_list->ports[i], &port_list->ports[i + 1], sizeof(wpr_port_entry_t) * (port_list->num_ports - i - 1));
            port_list->num_ports--;
            return 0; // success
        }
    }
    return -ENOENT; // port not found
}

/** 
* Delete a port by port ID.
* @param port_list
*   Pointer to the port list structure.
* @param port_id
*   Port ID of the port to delete.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_portlist_delete_byportid(wpr_ports_t *port_list, uint16_t port_id) {
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        if (port_list->ports[i].port_id == port_id) {
            wpr_free_port(&port_list->ports[i]);

            // Shift remaining ports down
            memmove(&port_list->ports[i], &port_list->ports[i + 1], sizeof(wpr_port_entry_t) * (port_list->num_ports - i - 1));
            port_list->num_ports--;
            return 0; // success
        }
    }
    return -ENOENT; // port not found
}

/** 
* Find a port by name.
* @param port_list
*   Pointer to the port list structure.
* @param name
*   Name of the port to find.
* @return
*   Pointer to the port structure, or NULL if not found.
**/
wpr_port_entry_t *wpr_find_port_byname(wpr_ports_t *port_list, const char *name)
{
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        if (strcmp(port_list->ports[i].name, name) == 0) {
            return &port_list->ports[i];
        }
    }
    return NULL; // port not found
}

wpr_port_entry_t *wpr_find_port_byid(wpr_ports_t *port_list, uint16_t port_id)
{
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        if (port_list->ports[i].port_id == port_id) {
            return &port_list->ports[i];
        }
    }
    return NULL; // port not found
}

wpr_port_entry_t *wpr_find_port_by_global_index(wpr_ports_t *port_list, uint16_t global_port_index)
{
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        if (port_list->ports[i].global_port_index == global_port_index) {
            return &port_list->ports[i];
        }
    }
    return NULL; // port not found
}



void wpr_portlist_print(wpr_ports_t *port_list){
    WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\n Dumping Global Port List: num_ports=%u\n", port_list->num_ports);
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
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

        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\tPort %u: Name=%s, PortID=%u, Type=%s, External=%s, Direction=%s, AdminState=%s, LinkState=%s, Speed=%u Mbps\n",
            i,
            port_list->ports[i].name,
            port_list->ports[i].port_id,
            (port_list->ports[i].kind == WPR_PORT_TYPE_ETHQ) ? "ETHQ" : "RING",
            port_list->ports[i].is_external ? "Yes" : "No",
            direction,

            port_list->ports[i].admin_state ? "Up" : "Down",
            port_list->ports[i].is_up ? "Up" : "Down",
            port_list->ports[i].speed_mbps);

        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tRX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_rx_queues; q++){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "%u ", port_list->ports[i].rx_queue_assignments[q]);
        }
        
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\n");
        
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tTX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_tx_queues; q++){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "%u ", port_list->ports[i].tx_queue_assignments[q]);
        }
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\n");    
    }
    return;
}

/** 
* Map ports to worker cores in a round-robin fashion.
* @param global_port_list
*   Pointer to the global port list structure.
* @param worker_cores
*   Number of worker cores.
* @return
*   Pointer to an array of core_port_mapping_t structures, one per worker core.
**/
int wpr_map_ports_to_workers(wpr_ports_t *global_port_list, unsigned int worker_cores)
{
    if (!global_port_list) {
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR,
                "wpr_map_ports_to_workers: global_port_list is NULL\n");
        return -EINVAL;
    }

    /* worker_cores = total lcores (IDs 0..worker_cores-1)
     * core 0 is the manager core
     * worker cores are 1..worker_cores-1
     */
    if (worker_cores < 2) {
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR,
                "wpr_map_ports_to_workers: need at least 1 worker core (worker_cores >= 2)\n");
        return -EINVAL;
    }

    unsigned int worker_count = worker_cores - 1;  /* number of worker cores (excluding mgr 0) */

    /* Round-robin indices into [0 .. worker_count-1] */
    unsigned int rr_rx = 0;
    unsigned int rr_tx = 0;

    for (unsigned int i = 0; i < global_port_list->num_ports; i++) {
        wpr_port_entry_t *port = &global_port_list->ports[i];

        /* Manager-only special case: everything pinned to core 0 */
        if (port->dir == WPR_PORT_RXTX_MGRONLY) {
            for (uint16_t q = 0; q < port->total_rx_queues; q++) {
                port->rx_queue_assignments[q] = 0;
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                        "Assigned RX queue %u of port %s to MGR core 0\n",
                        q, port->name);
            }
            for (uint16_t q = 0; q < port->total_tx_queues; q++) {
                port->tx_queue_assignments[q] = 0;
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                        "Assigned TX queue %u of port %s to MGR core 0\n",
                        q, port->name);
            }
            /* Do not touch rr_rx / rr_tx */
            continue;
        }

        /* Validate direction */
        if (port->dir != WPR_PORT_RX &&
            port->dir != WPR_PORT_TX &&
            port->dir != WPR_PORT_RXTX)
        {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR,
                    "Invalid port direction %d for port %s\n",
                    port->dir, port->name);
            return -EINVAL;
        }

        if(port->kind == WPR_PORT_TYPE_DROP){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                    "Skipping queue assignment for drop port %s\n",
                    port->name);
            continue;
        }

        /* RX: round-robin over worker cores 1..worker_cores-1 */
        if (port->dir == WPR_PORT_RX || port->dir == WPR_PORT_RXTX) {
            for (uint16_t q = 0; q < port->total_rx_queues; q++) {
                unsigned int core_id = (rr_rx % worker_count) + 1;  /* 1..worker_cores-1 */

                port->rx_queue_assignments[q] = core_id;
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                        "Assigned RX queue %u of port %s to core %u\n",
                        q, port->name, core_id);

                rr_rx = (rr_rx + 1) % worker_count;
            }
        }

        /* TX: round-robin over worker cores 1..worker_cores-1 */
        if (port->dir == WPR_PORT_TX || port->dir == WPR_PORT_RXTX) {
            for (uint16_t q = 0; q < port->total_tx_queues; q++) {
                unsigned int core_id = (rr_tx % worker_count) + 1;  /* 1..worker_cores-1 */

                port->tx_queue_assignments[q] = core_id;
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                        "Assigned TX queue %u of port %s to core %u\n",
                        q, port->name, core_id);

                rr_tx = (rr_tx + 1) % worker_count;
            }
        }
    }

    //map drop port explicitly 
    wpr_port_entry_t *drop_port = wpr_find_port_byname(global_port_list, "drop_port");
    if(!drop_port){
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "Drop port not found in global port list\n");
        return -ENOENT;
    }

    for(unsigned int i=0; i<worker_cores;i++){
        drop_port->tx_queue_assignments[i] = i; //all cores can access drop port tx queue 0
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                "Assigned TX queue 0 of drop port %s to core %u\n",
                drop_port->name, i);
    }

    return 0;
}



/**
    * Get the port ID for a given PCI bus address.
    *
    * @param bdf
    *   PCI bus address string (e.g., "0000:01:00.0").
    * @param[out] port_id_out
    *   Will be set to the port ID on success.
    *
    * @return
    *   - 0 on success
    *   - -ENOENT if the port ID could not be found
    *   - -EINVAL if input parameters are invalid
**/
int wpr_get_port_id_by_pci_addr(const char *bdf, uint16_t *port_id_out)
{
    if (!bdf || !port_id_out)
        return -EINVAL;

    /* Fast path: for PCI devices the ethdev "name" is the BDF */
    if (rte_eth_dev_get_port_by_name(bdf, port_id_out) == 0)
        return 0;

    /* Fallback: iterate ports and compare names */
    uint16_t pid;
    RTE_ETH_FOREACH_DEV(pid) {
        char name[RTE_ETH_NAME_MAX_LEN] = {0};
        if (rte_eth_dev_get_name_by_port(pid, name) == 0) {
            if (strcmp(name, bdf) == 0) {
                *port_id_out = pid;
                return 0;
            }
        }
    }

    return -ENOENT;
}


int wpr_port_config_queues(uint16_t portid, uint16_t rx_rings, uint16_t tx_rings, uint16_t nb_rxd, uint16_t nb_txd, 
    struct rte_mempool *mbuf_pool, struct rte_eth_rxconf *rxq_conf, struct rte_eth_txconf *txconf)
{
    int retval = 0;
    /* Queue configuration */
    //Allocate and set up N RX queues per lcore. Note, for Pcap Replay we don't current use Rx processing
    //but setting it up just becase I may want to extend the app to support sequence checking in the future.
    uint16_t q;
    for (q = 0; q < rx_rings; q++) {
            retval = rte_eth_rx_queue_setup(portid, q, nb_rxd, rte_eth_dev_socket_id(portid), rxq_conf, mbuf_pool);
            if (retval < 0) {
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError setting up rx queue %"PRIu16 " for port %"PRIu16 "\n",q,portid);
                return -ENOTSUP;
            }
    }

    //Allocate and set up N TX queues per lcore. 
    for (q = 0; q < tx_rings; q++) {

            /* Reclaim frequently; match your burst size. */
            txconf->tx_rs_thresh   = RTE_MAX((uint16_t)32,  (uint16_t)(nb_txd / 16));
            txconf->tx_free_thresh = RTE_MAX((uint16_t)64,  (uint16_t)(nb_txd / 8));

            /* Keep constraints: tx_rs_thresh <= tx_free_thresh < nb_tx_desc-3 */
            if (txconf->tx_rs_thresh   >= nb_txd)   txconf->tx_rs_thresh = nb_txd - 8;
            if (txconf->tx_free_thresh >= nb_txd)   txconf->tx_free_thresh = nb_txd - 8;
            if (txconf->tx_rs_thresh   >  txconf->tx_free_thresh) txconf->tx_rs_thresh = txconf->tx_free_thresh;

            retval = rte_eth_tx_queue_setup(portid, q, nb_txd, rte_eth_dev_socket_id(portid), txconf);
            if (retval < 0) {
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError setting up tx queue %"PRIu16 " for port %"PRIu16 "\n",q,portid);
                return -ENOTSUP;
            }
    }

    return 0;
}

/**
    * Initialize a DPDK Ethernet port.
    *
    * @param port
    *   Port ID to initialize.
    * @param mbuf_pool
    *   Mempool to use for RX/TX buffers.
    * @param wpr_app_cfg
    *   Pointer to the application configuration.
    *
    * @return
    *   - 0 on success
    *   - -ENOENT if the port ID is invalid or other errors occur
    *   - -ENOTSUP if the port configuration is not supported
**/
int wpr_port_init(wpr_port_entry_t *port_entry, uint16_t port, struct rte_mempool *mbuf_pool, wpr_portinit_cfg_t *port_init_cfg)
{
        struct rte_eth_conf port_conf;
        const uint16_t rx_rings_req = port_init_cfg->num_rxq;
        const uint16_t tx_rings_req = port_init_cfg->num_txq;
        uint16_t nb_rxd = port_init_cfg->rx_ring_size;
        uint16_t nb_txd = port_init_cfg->tx_ring_size;
        int retval;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        //check if port number is valid 
        if (!rte_eth_dev_is_valid_port(port)){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tInvalid port ID %"PRIu16 "\n",port);
            return -ENOENT;
        }

        //get device info structure 
        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError getting device info for port %"PRIu16 "\n",port);
            return -ENOENT;
        }

        //initialize port configuration structure 
        memset(&port_conf, 0, sizeof(struct rte_eth_conf));
        
        struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
        
        /* Disabled - bug with I226 nic and rx timestamping
        if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tPort %u supports RX timestamps\n", port);
            port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
            rxq_conf.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
        } 
        else {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_WARNING, "\t\tPort %"PRIu16 " does not support RX timestamps\n",port);
        }*/

        /* Configure port properties based on device info and other factors */
        //do not use fast free mbufs since we are sending clones
        if (port_init_cfg->tx_multiseg_offload){
            if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS){
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tEnabling multi-segment offload on port %"PRIu16 "\n",port);
                port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
            }
        }

        //configure tx checksum offloads if enabled in config
        if (port_init_cfg->tx_ip_checksum_offload){
            if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM){
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tEnabling IPv4 checksum offload on port %"PRIu16 "\n",port);
                port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
            }
        }

        if (port_init_cfg->tx_tcp_checksum_offload){
            if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM){
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tEnabling TCP checksum offload on port %"PRIu16 "\n",port);
                port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
            }
        }   

        if (port_init_cfg->tx_udp_checksum_offload){
            if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM){
                WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, "\t\tEnabling UDP checksum offload on port %"PRIu16 "\n",port);
                port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
            }
        }   

        /* Enable RSS multi-queue */
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

        /* Choose which flows participate in RSS */
        uint64_t rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;

        /* Mask with NIC capabilities */
        rss_hf &= dev_info.flow_type_rss_offloads;
        if (rss_hf == 0) {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_WARNING,
                    "\t\tPort %u: NIC does not support requested RSS types, using default\n",
                    port);
            rss_hf = dev_info.flow_type_rss_offloads;
        }
        else{
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO,
                    "\t\tPort %u: Configuring RSS for flows: %s%s%s\n",
                    port,
                    (rss_hf & RTE_ETH_RSS_IP)  ? "IP "  : "",
                    (rss_hf & RTE_ETH_RSS_TCP) ? "TCP " : "",
                    (rss_hf & RTE_ETH_RSS_UDP) ? "UDP " : "");
        }

        port_conf.rx_adv_conf.rss_conf = (struct rte_eth_rss_conf) {
            .rss_key = NULL,                    // use NIC default key
            .rss_key_len = 0,
            .rss_hf = rss_hf,
        };

        /* Configure the Ethernet device. */
        //one rx/tx ring pair per worker port 
        unsigned int rx_rings = RTE_MIN(dev_info.max_rx_queues, rx_rings_req);
        unsigned int tx_rings = RTE_MIN(dev_info.max_tx_queues, tx_rings_req);


        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError configuring port %"PRIu16 "\n",port);
            return -ENOTSUP;
        }
        //set rx/tx ring sizes 
        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError adjusting rx/tx desc for port %"PRIu16 "\n",port);
            return -ENOTSUP;
        }

        //configure queues 
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        retval = wpr_port_config_queues(port, rx_rings, tx_rings, nb_rxd, nb_txd, mbuf_pool, &rxq_conf, &txconf);
        if (retval != 0){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError configuring queues for port %"PRIu16 "\n",port);
            return retval;
        }

        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0) {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError starting port %"PRIu16 "\n",port);
            return -ENOENT;
        }   

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        retval = rte_eth_macaddr_get(port, &addr);
        if (retval != 0) {
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError getting MAC address for port %"PRIu16 "\n",port);
            return -ENOENT;
        }

        char bdf[64];
        rte_eth_dev_get_name_by_port(port, bdf);
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_INFO, 
                "\t\tPort %u MAC: %02x:%02x:%02x:%02x:%02x:%02x, PCI Bus ID: %s\n",
                port,
                addr.addr_bytes[0], addr.addr_bytes[1],
                addr.addr_bytes[2], addr.addr_bytes[3],
                addr.addr_bytes[4], addr.addr_bytes[5],
                bdf);

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        if (retval != 0){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError enabling promiscuous mode for port %"PRIu16 "\n",port);  
            return -ENOTSUP;
        }

        //make sure port is down to start with
        retval = rte_eth_dev_set_link_down(port);
        if (retval != 0){
            WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "\t\tError setting link down for port %"PRIu16 "\n",port);  
            return -ENOTSUP;
        }

        //update port entry cached parameters
        port_entry->total_rx_queues = rx_rings;
        port_entry->total_tx_queues = tx_rings;
        port_entry->nb_rxd = nb_rxd;
        port_entry->nb_txd = nb_txd;

        port_entry->mbuf_pool = mbuf_pool;
        port_entry->mac_addr  = addr;
        port_entry->port_conf = port_conf;
        port_entry->rxq_conf = rxq_conf;
        port_entry->txq_conf = txconf;


        return 0;
}

/** 
* Set the administrative link state of a DPDK Ethernet port.
* @param port_entry
*   Port entry to configure.
* @param admin_up
*   If true, bring the link up; if false, bring the link down.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_port_set_link_state(wpr_port_entry_t *port_entry, bool admin_up)
{
    int rc;

    if(port_entry->is_external == false){
        WPR_LOG(WPR_LOG_PORTS, RTE_LOG_ERR, "Cannot set link state on internal port %s\n", port_entry->name);
        return -EINVAL;
    }

    uint16_t port_id = port_entry->port_id;

    if (admin_up) {
        rc = rte_eth_dev_set_link_up(port_id);
        if (rc < 0)
            return rc;  /* -ENODEV, etc. */

    } else {
        rc = rte_eth_dev_set_link_down(port_id);
        if (rc < 0)
            return rc;  /* -ENODEV, etc. */
    }

    port_entry->admin_state = admin_up;
    return 0;
}

/* --------------------------------------- Port Stats Handlers -------------------------------------------*/

/**
* Initialize port statistics for a given port entry. Allocates and initializes all required memory. 
* @param port_entry
*   Pointer to the port entry structure.
* @return
*   n stats count on success, negative errno on failure.
**/
int wpr_port_stats_init(wpr_port_entry_t *port_entry){
    //initialize port stat lock for this port 
    
    int num_stats = 0;
    pthread_mutex_init(&port_entry->stats.lock, NULL);

    if(port_entry->kind == WPR_PORT_TYPE_ETHQ){
        port_entry->stats.port_kind = WPR_PORT_TYPE_ETHQ;

        //get number of xstats for this port
        int n_xstats = rte_eth_xstats_get(port_entry->port_id, NULL, 0);
        if (n_xstats < 0) {
            return -EINVAL;
        }
        

        //initialize xstat names array
        port_entry->stats.xstats.n_xstats            = n_xstats;
        port_entry->stats.xstats.n_xstats_total      = n_xstats * 2; //include rate stats
        port_entry->stats.xstats.port_stats_names    = rte_zmalloc("port_xstat_names",
                                                                sizeof(struct rte_eth_xstat_name) * n_xstats,
                                                                RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.xstats.port_stats_names == NULL) {
            return -ENOMEM;
        }

        port_entry->stats.xstats.port_stats_names_rates    = rte_zmalloc("port_xstat_names_rates",
                                                                sizeof(struct rte_eth_xstat_name) * n_xstats,
                                                                RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.xstats.port_stats_names_rates == NULL) {
            return -ENOMEM;
        }

        //initialize stats data - previous sample
        port_entry->stats.xstats.prev_port_stats = rte_zmalloc("prev_port_xstats",
                                                                sizeof(struct rte_eth_xstat) * n_xstats,
                                                                RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.xstats.prev_port_stats == NULL) {
            return -ENOMEM;
        }

        //initialize stats data - current sample
        port_entry->stats.xstats.current_port_stats = rte_zmalloc("current_port_xstats",
                                                                sizeof(struct rte_eth_xstat) * n_xstats,
                                                                RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.xstats.current_port_stats == NULL) {
            return -ENOMEM;
        }

        //initialize stats data - rate stats 
        port_entry->stats.xstats.rates_port_stats = rte_zmalloc("rates_port_xstats",
                                                                sizeof(struct rte_eth_xstat) * n_xstats,
                                                                RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.xstats.rates_port_stats == NULL) {
            return -ENOMEM;
        }

        //preload xstat names array so we don't have to do it later
        int ret = rte_eth_xstats_get_names(port_entry->port_id, port_entry->stats.xstats.port_stats_names, n_xstats);
        if (ret < 0 || ret > n_xstats){
            return -EINVAL;
        }


        for (int i = 0; i < n_xstats; i++) {
            char *dst = port_entry->stats.xstats.port_stats_names_rates[i].name;
            const char *src = port_entry->stats.xstats.port_stats_names[i].name;

            /* We need room for src + "_rate" + '\0'
            * So limit src to (RTE_ETH_XSTATS_NAME_SIZE - 1 - WPR_RATE_SUFFIX_LEN)
            */
            const int max_src_len = RTE_ETH_XSTATS_NAME_SIZE - 1 - WPR_RATE_SUFFIX_LEN;
            const int src_len = max_src_len > 0 ? max_src_len : 0;

            snprintf(dst,RTE_ETH_XSTATS_NAME_SIZE,"%.*s%s",src_len,src,WPR_RATE_SUFFIX);
        }

        num_stats = n_xstats;
    }
    else if (port_entry->kind == WPR_PORT_TYPE_RING){
        port_entry->stats.port_kind = WPR_PORT_TYPE_RING;
        port_entry->stats.ringstats.n_stats = RTE_DIM(WPR_PORT_RINGSTAT_NAMES);
        port_entry->stats.ringstats.n_stats_total = port_entry->stats.ringstats.n_stats * 2; //include rate stats
        port_entry->stats.ringstats.ring_stats_names = &WPR_PORT_RINGSTAT_NAMES[0];

        port_entry->stats.ringstats.ring_stats_names_rates = rte_zmalloc("ring_stats_names_rates",
                                                                        sizeof(wpr_ring_stats_name_t) * port_entry->stats.ringstats.n_stats,
                                                                        RTE_CACHE_LINE_SIZE);
        if (port_entry->stats.ringstats.ring_stats_names_rates == NULL) {
            return -ENOMEM;
        }

        for (int i = 0; i < port_entry->stats.ringstats.n_stats; i++) {
            char *dst = port_entry->stats.ringstats.ring_stats_names_rates[i].name;
            const char *src = port_entry->stats.ringstats.ring_stats_names[i].name;

            /* We need room for src + "_rate" + '\0'
            * So limit src to (RTE_ETH_XSTATS_NAME_SIZE - 1 - WPR_RATE_SUFFIX_LEN)
            */
            const int max_src_len = RTE_ETH_XSTATS_NAME_SIZE - 1 - WPR_RATE_SUFFIX_LEN;
            const int src_len = max_src_len > 0 ? max_src_len : 0;

            snprintf(dst,RTE_ETH_XSTATS_NAME_SIZE,"%.*s%s",src_len,src,WPR_RATE_SUFFIX);
        }

        //initialize stats data - previous sample
        port_entry->stats.ringstats.prev_ring_stats = rte_zmalloc("prev_ring_port_stats",
                                                                        sizeof(wpr_ring_stats_shard_t),
                                                                        RTE_CACHE_LINE_SIZE);

        if (port_entry->stats.ringstats.prev_ring_stats == NULL) {
            return -ENOMEM;
        }   

        //initialize stats data - current sample
        port_entry->stats.ringstats.current_ring_stats = rte_zmalloc("current_ring_port_stats",
                                                                        sizeof(wpr_ring_stats_shard_t),
                                                                        RTE_CACHE_LINE_SIZE);

        if (port_entry->stats.ringstats.current_ring_stats == NULL) {
            return -ENOMEM;
        }

        //initialize stats data - rate stats 
        port_entry->stats.ringstats.rates_ring_stats = rte_zmalloc("rates_ring_port_stats",
                                                                        sizeof(wpr_ring_stats_shard_t),
                                                                        RTE_CACHE_LINE_SIZE);

        if (port_entry->stats.ringstats.rates_ring_stats == NULL) {
            return -ENOMEM;
        }
        num_stats = port_entry->stats.ringstats.n_stats;
    }   
    else if (port_entry->kind == WPR_PORT_TYPE_DROP){
        // do nothing
    }

    //Initialize timestamps
    clock_gettime(CLOCK_MONOTONIC, &port_entry->stats.prev_ts);
    clock_gettime(CLOCK_MONOTONIC, &port_entry->stats.curr_ts);

    return num_stats;
}

/** 
* Free port statistics for a given port entry. Frees all allocated memory.
* @param port_entry
*   Pointer to the port entry structure.
* @return
*   0 on success, negative errno on failure.
**/
int wpr_port_stats_free(wpr_port_entry_t *port_entry){
    //free port stats memory 
    pthread_mutex_destroy(&port_entry->stats.lock);

    if(port_entry->kind == WPR_PORT_TYPE_ETHQ){
        rte_free(port_entry->stats.xstats.port_stats_names);
        rte_free(port_entry->stats.xstats.port_stats_names_rates);
        rte_free(port_entry->stats.xstats.prev_port_stats);
        rte_free(port_entry->stats.xstats.current_port_stats);
        rte_free(port_entry->stats.xstats.rates_port_stats);
    }
    else if (port_entry->kind == WPR_PORT_TYPE_RING){
        rte_free(port_entry->stats.ringstats.ring_stats_names_rates);   
        rte_free(port_entry->stats.ringstats.prev_ring_stats);
        rte_free(port_entry->stats.ringstats.current_ring_stats);
        rte_free(port_entry->stats.ringstats.rates_ring_stats);
    }
    else if (port_entry->kind == WPR_PORT_TYPE_DROP){
        // do nothing
    }

    return 0;
}   

