/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_ports.h
Description: the ports API is responsible for managing all ports in the system, including physical NIC ports and ring based ports. it includes logic for 
building and maintaining a global port list structure that contains all ports in the system along with their parameters. it also includes logic for 
initializing physical ports via DPDK and setting up ring based ports. the ports API also provides a simple dynamic array implementation for managing the list 
of ports.

During initialization, the ports API is used to create the global port list based on the application configuration, and assign ports and queues to worker cores.
the global port list is then passed to other subsystems such as the egress table and packet I/O API to allow them to interact with ports in a uniform manner. The
heart of the ports API is the ppr_port_entry_t struct which contains all relevant information about a port, including its type (physical or ring), port ID, queue assignments,
and statistics. The ports API also includes functions for adding, deleting, and finding ports in the global port list, as well as printing the port list for 
debugging purposes.

*/

#ifndef PPR_PORTS_H
#define PPR_PORTS_H
#include <stdatomic.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

#define PPR_MAX_RINGSTAT_NAME_LEN 32
#define PPR_RATE_SUFFIX      "_rate"
#define PPR_RATE_SUFFIX_LEN  (sizeof(PPR_RATE_SUFFIX) - 1) /* 5 */

/* Forward declarations for types only used via pointer in this header */
//from ppr_ctldev_mgr.h
typedef struct ppr_ctldev_ctx          ppr_ctldev_ctx_t;
typedef struct ppr_ports               ppr_ports_t;


/* Enum for port type */
typedef enum {
    PPR_PORT_TYPE_ETHQ = 0,
    PPR_PORT_TYPE_RING = 1,
    PPR_PORT_TYPE_DROP = 2,
} ppr_port_kind_t;

/* Enum for port direction, what a worker can do with the port */
typedef enum ppr_port_dir{
    PPR_PORT_RX = 0,
    PPR_PORT_TX = 1,
    PPR_PORT_RXTX = 2,
    PPR_PORT_RXTX_MGRONLY =3, //special case for vtap ports only handled by manager core
} ppr_port_dir_t;

/* Port and Port list structs */
typedef struct ppr_ring_stats_name{
    char name[PPR_MAX_RINGSTAT_NAME_LEN];
} ppr_ring_stats_name_t;

// ring stats struct for ring based ports
typedef struct ppr_ring_stats_shard {
    uint64_t enq_pkts;
    uint64_t deq_pkts;
    uint64_t drop_pkts;
} ppr_ring_stats_shard_t __rte_cache_aligned ;

//wrapper around rte_ring to unclude per worker core stats 
typedef struct ppr_ring_port{
    struct rte_ring *ring;
    ppr_ring_stats_shard_t *stats_shard; //per worker core stats pointer    
} ppr_ring_port_t;

//stats struct for holding physical port xstats 
typedef struct ppr_single_port_xstats {
    int n_xstats;
    int n_xstats_total;
    struct rte_eth_xstat_name   *port_stats_names;     
    struct rte_eth_xstat_name   *port_stats_names_rates;               
    struct rte_eth_xstat        *prev_port_stats;
    struct rte_eth_xstat        *current_port_stats; 
    struct rte_eth_xstat        *rates_port_stats;     
} ppr_single_port_xstats_t;

//stats struct for holding ring based port stats
typedef struct ppr_single_port_ringstats {
    int n_stats; 
    int n_stats_total;
    ppr_ring_stats_name_t  *ring_stats_names;
    ppr_ring_stats_name_t  *ring_stats_names_rates;
    ppr_ring_stats_shard_t *prev_ring_stats;
    ppr_ring_stats_shard_t *current_ring_stats;
    ppr_ring_stats_shard_t *rates_ring_stats;
} ppr_single_port_ringstats_t;

//stats struct to unify different port kinds
typedef struct ppr_single_port_stats2{
    pthread_mutex_t lock; 
    ppr_port_kind_t  port_kind;
    const char *name;
    union {
        ppr_single_port_xstats_t    xstats;
        ppr_single_port_ringstats_t ringstats;
    };
    struct timespec prev_ts; 
    struct timespec curr_ts;
} ppr_single_port_stats_t;


typedef struct ppr_portinit_cfg {
    uint16_t num_rxq;
    uint16_t num_txq;
    uint16_t rx_ring_size;
    uint16_t tx_ring_size;
    bool       tx_ip_checksum_offload;
    bool       tx_tcp_checksum_offload;
    bool       tx_udp_checksum_offload;
    bool       tx_multiseg_offload;
} ppr_portinit_cfg_t;


typedef struct ppr_port_entry{
    //Port identifiers 
    char *name; 
    ppr_port_kind_t kind;

    //the dpdk / internal access ID 
    uint16_t port_id; 

    //the ID used by everyone else to index this port 
    uint16_t global_port_index; 

    
    ppr_ports_t *parent_port_list; //pointer back to parent port list
    bool is_external;
    ppr_port_dir_t dir;

    //cached port config structs 
    struct rte_ether_addr mac_addr;
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_mempool *mbuf_pool;
    uint16_t nb_rxd;
    uint16_t nb_txd;
    
    //traffic gen related info 
    _Atomic bool tx_enabled; //is tx enabled on this port

    //port state info (reported)
    bool admin_state;
    bool is_up;
    uint32_t speed_mbps;
    bool autoneg;

    //port state info (configured)
    _Atomic bool is_reconfiguring;
    uint32_t cfg_link_speed_mbps;
    bool     cfg_autoneg;
    bool     cfg_duplex_full;
    uint32_t cfg_adv_speed_mask;

    //Queue information 
    uint16_t total_rx_queues;
    uint16_t total_tx_queues;

    //what worker cores are assigned each queue 
    uint16_t *rx_queue_assignments;
    uint16_t *tx_queue_assignments;

    //port stats
    ppr_single_port_stats_t stats;

} ppr_port_entry_t;

/* Struct to track all configured ports in the system */
typedef struct ppr_ports{
    unsigned int    num_ports;
    unsigned int    port_capacity;
    ppr_port_entry_t *ports;

} ppr_ports_t;


/* Function prototypes for port management */
//port dynamic array management
int ppr_port_list_init(ppr_ports_t **port_list_ptr);
void ppr_port_list_free(ppr_ports_t *port_list);
int ppr_free_port(ppr_port_entry_t *port);

//add/delete/find/print ports in port list
int ppr_portlist_add(ppr_ports_t *port_list, const char * name, uint16_t port_id, 
    bool is_external,ppr_port_kind_t kind, uint16_t total_rx_queues, uint16_t total_tx_queues, ppr_port_dir_t dir);
int ppr_portlist_delete_byname(ppr_ports_t *port_list, const char *port_name);
int ppr_portlist_delete_byportid(ppr_ports_t *port_list, uint16_t port_id);
ppr_port_entry_t *ppr_find_port_byname(ppr_ports_t *port_list, const char *name);
ppr_port_entry_t *ppr_find_port_byid(ppr_ports_t *port_list, uint16_t port_id);
ppr_port_entry_t *ppr_find_port_by_global_index(ppr_ports_t *port_list, uint16_t global_port_index);
void ppr_portlist_print(ppr_ports_t *port_list);

//assign ports to worker cores based on runtime config and probed resources
int ppr_map_ports_to_workers(ppr_ports_t *global_port_list, unsigned int worker_cores);

//functions for interacting and initializing physical ports
int ppr_get_port_id_by_pci_addr(const char *bus_addr, uint16_t *port_id_out);
int ppr_port_init(ppr_port_entry_t *port_entry, uint16_t port, struct rte_mempool *mbuf_pool, ppr_portinit_cfg_t *port_init_cfg);
int ppr_port_config_queues(uint16_t portid, uint16_t rx_rings, uint16_t tx_rings, uint16_t nb_rxd, uint16_t nb_txd, 
    struct rte_mempool *mbuf_pool, struct rte_eth_rxconf *rxq_conf, struct rte_eth_txconf *txconf);

int ppr_port_stats_init(ppr_port_entry_t *port_entry);
int ppr_port_stats_free(ppr_port_entry_t *port_entry);


#endif