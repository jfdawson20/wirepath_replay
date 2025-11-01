/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: buff_worker.c 
Description: Primary entry point and supporting code for DPDK buffer filler threads. 
buffer threads are responsible for reading pcap mbuffs from template memory, creating mbuf clones 
and adding them to the shared double buffer structures that link buffer to tx threads. 

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <unistd.h>
#include <sys/random.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <limits.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

/* Local Project Includes */
#include "buff_worker.h"
#include "app_defines.h"
#include "pcap_loader.h"
#include "mbuf_fields.h"
#include "flowtable.h"

#define AUTO_FLUSH_CYCLES 10000

/* helper function, used to generate a random start time per virtual flow in dynamic expansion mode */
uint64_t rand_u64_uniform(uint64_t max)
{
    if (max == 0) return 0;
    uint64_t r;
    int ret = 0;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % (max + 1));
    do {
        ret = getrandom(&r, sizeof(r), 0);
        if (ret < 0){
            rte_exit(EXIT_FAILURE, "getrandom call failed, shouldn't ever happen\n");
        }
    } while (r >= limit);
    return r % (max + 1);
}

/* Primary buffer filler function for running in direct replay mode. In this mode, a single buffer core reads a pcap mbuf array in sequence on repeat.
   the assumption is the pcap array assigned to each buffer core is a flow affinity "slice" of a larger pcap, basically the main pcap has been preprocessed
   prior to loading it into memory so that 1 pcap becomes N pcaps (number of tx core + buffer filler core pairs) to preserve flow affinity while scaling
   performance. This means that the single flow max pps rate is capped at whatever a single tx core + buffer core pair can achieve. 
   
   This mode is a dumb replay, it does not consider anything about the original pcap's timing parameters, it will transmit the sequence (infinite repeats)*/
static __rte_always_inline int process_direct_replay(struct pcap_mbuff_slot pcap_buffer, struct rte_ring *tx_ring, 
    unsigned int *cur_index, unsigned int chunk_size, struct rte_mempool *clonepool){
    
    int j =0;
    struct rte_mbuf *clones[RING_BURST];
    const unsigned int cnt = pcap_buffer.mbuf_array[0].count;

    /* iterate over pcap buffer indexed by the slot assignment, pick up where we last left off with this port via 
       pcap_cur_index we maintain for each port */
    for(j=*cur_index; j < *cur_index + chunk_size ;j++){
        
        // if we've reached the end of the pcap array, reset and process first chunk
        if (j >= cnt){
            *cur_index = 0; 
            return 0;
        }  

        //set the burst size either to RING_BURST or whatever the remaining number of packets is 
        unsigned int remaining = cnt - j;
        uint16_t burst_cnt = (remaining < RING_BURST) ? remaining : RING_BURST;

        //clone next RING_BURST amount of cloned packets 
        //guard creation loop, check for clone failures and bail and flag if clone failures occured
        uint16_t created = 0;
        for (; created < burst_cnt; created++) {
            struct rte_mbuf *tmpl = pcap_buffer.mbuf_array[0].pkts[j + created];

            // Sanity: template must be direct, immutable, refcnt==1
            RTE_ASSERT(!RTE_MBUF_INDIRECT(tmpl));
            RTE_ASSERT(rte_mbuf_refcnt_read(tmpl) == 1);

            struct rte_mbuf *c = rte_pktmbuf_clone(tmpl, clonepool);
            if (unlikely(c == NULL)) {
                printf("failed to clone\n");
                break; // pool pressure: just send the ones we cloned
            }
            clones[created] = c;
        }
        if (created == 0) {
            // Nothing cloned right now; yield a bit and retry next call
            rte_pause();
            *cur_index = j;
            return 0;
        }

        //add to rx_ring
        // multi-producer enqueue; try burst, if ring is full re-try, we want to backpressure 
        uint16_t enqueued = 0;
        uint16_t tx_n = 0;
        int waiting = 0;
        while (enqueued < created) {
            tx_n = rte_ring_mp_enqueue_burst(tx_ring, (void * const*)(clones+enqueued), created-enqueued, NULL);
            rte_pause();
            enqueued += tx_n;
            waiting++;
        }

        //increment j (pcap packet index) but number of packets we've processed
        j+=created;
    }
    
    *cur_index = j % cnt; 

    return 0;
}

static inline int ipv6_find_l4(const struct rte_ipv6_hdr *ip6,
                               const uint8_t *pkt_end,
                               uint8_t *out_proto,
                               const uint8_t **out_l4)
{
    const uint8_t *p = (const uint8_t *)(ip6 + 1);
    uint8_t nh = ip6->proto;
    int hdr_ext_limit = 8; // reasonable cap

    while (hdr_ext_limit-- > 0) {
        if (nh == IPPROTO_TCP || nh == IPPROTO_UDP || nh == IPPROTO_ICMPV6) {
            *out_proto = nh;
            *out_l4 = p;
            return 0;
        }

        /* Known extension headers use length in 8-octet units (excluding first 8 bytes) */
        if (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
            nh == IPPROTO_FRAGMENT || nh == IPPROTO_AH ||
            nh == IPPROTO_DSTOPTS) {
            if (p + 2 > pkt_end) return -1;
            uint8_t next = p[0];
            uint8_t extlen = p[1]; // unit depends on EH kind
            size_t hdr_len;

            if (nh == IPPROTO_AH) {
                // AH length is (extlen+2)*4 bytes
                hdr_len = (size_t)(extlen + 2) * 4u;
            } else {
                // Others: (extlen+1)*8 bytes
                hdr_len = (size_t)(extlen + 1) * 8u;
            }

            if (p + hdr_len > pkt_end) return -1;
            nh = next;
            p += hdr_len;
            continue;
        }

        // Unknown/unsupported EH
        return -1;
    }
    return -1;
}

static __rte_always_inline int
modify_mbufclone_hdrs(struct flow_table *ft, struct rte_mbuf *c,
                      uint32_t core_id, uint32_t vert_id)
{
    uint32_t pkt_len = rte_pktmbuf_pkt_len(c);
    if (pkt_len < sizeof(struct rte_ether_hdr))
        return -1;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(c, struct rte_ether_hdr *);
    uint16_t l2_len = sizeof(*eth);
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
    uint32_t off = sizeof(struct rte_ether_hdr);

    /* Single 802.1Q (extend as needed for QinQ) */
    if (etype == RTE_ETHER_TYPE_VLAN) {
        if (pkt_len < off + sizeof(struct rte_vlan_hdr)) return -1;
        struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *)((uint8_t *)eth + off);
        etype = rte_be_to_cpu_16(vh->eth_proto);
        off += sizeof(struct rte_vlan_hdr);
        l2_len += sizeof(struct rte_vlan_hdr);
    }

    /* Build unified flow key (IPv4 or IPv6) */
    struct flow5 key;
    uint8_t *base = (uint8_t *)eth;
    const uint8_t *pkt_end = base + pkt_len;

    uint8_t l4_proto = 0;
    const uint8_t *l4_ptr = NULL;

    if (etype == RTE_ETHER_TYPE_IPV4) {
        if (pkt_len < off + sizeof(struct rte_ipv4_hdr)) return -1;
        struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)((uint8_t *)eth + off);
        if ((ip4->version_ihl >> 4) != 4) return -1;

        /* Drop non-first fragments */
        if ((ip4->fragment_offset & rte_cpu_to_be_16(RTE_IPV4_HDR_OFFSET_MASK)) != 0)
            return -1;

        uint16_t ihl_bytes = (ip4->version_ihl & 0x0F) * 4;
        if (pkt_len < off + ihl_bytes) return -1;

        l4_proto = ip4->next_proto_id;
        l4_ptr = (const uint8_t *)ip4 + ihl_bytes;

        /* Extract ports if TCP/UDP; fields are BE16 on the wire */
        uint16_t sport_be = 0, dport_be = 0;
        if (l4_proto == IPPROTO_TCP) {
            if (l4_ptr + sizeof(struct rte_tcp_hdr) > pkt_end) return -1;
            const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)l4_ptr;
            sport_be = tcp->src_port; dport_be = tcp->dst_port;
        } else if (l4_proto == IPPROTO_UDP) {
            if (l4_ptr + sizeof(struct rte_udp_hdr) > pkt_end) return -1;
            const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)l4_ptr;
            sport_be = udp->src_port; dport_be = udp->dst_port;
        } else {
            // If you don’t want to handle others, bail
            // printf("Unsupported L4 proto %u\n", l4_proto);
            return -1;
        }

        /* Build IPv4 key (expects BE) */
        ft_key_from_ipv4(&key, ip4->src_addr, ip4->dst_addr, sport_be, dport_be, l4_proto);
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

        /* Lookup action */
        const struct ft_action *act = ft_lookup(ft, &key);

        switch (act->kind) {
        case FT_ACT_NOP:
            break;
        case FT_ACT_DROP:
            return -2;

        case FT_ACT_REWRITE_L2:
        case FT_ACT_REWRITE_L2L3:
        case FT_ACT_REWRITE_L2L3L4:
            if (act->src_mac_valid) eth->src_addr = act->new_src_mac;
            if (act->dst_mac_valid) eth->dst_addr = act->new_dst_mac;
            /* fallthrough for L3/L4 parts */
            if (act->kind == FT_ACT_REWRITE_L2) break;
            /* no break */

        case FT_ACT_REWRITE_L3:
        case FT_ACT_REWRITE_L3L4:
            /* IPv4-only L3 rewrite (your struct is v4-centric) */
            if (act->src_ip_valid) {
                ip4->src_addr = htonl(ntohl(act->new_src_ip_subnet) + (core_id << 16) + vert_id);
            }
            if (act->dst_ip_valid) {
                ip4->dst_addr = htonl(ntohl(act->new_dst_ip_subnet) + (core_id << 16) + vert_id);
            }
            if (act->kind == FT_ACT_REWRITE_L3) break;
            /* fallthrough to L4 */

        case FT_ACT_REWRITE_L4: {
            if (l4_proto == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
                if (act->sport_valid) tcp->src_port = act->new_sport;
                if (act->dport_valid) tcp->dst_port = act->new_dport;
            } else if (l4_proto == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
                if (act->sport_valid) udp->src_port = act->new_sport;
                if (act->dport_valid) udp->dst_port = act->new_dport;
            }
            break;
        }
        default:
            break;
        }

        /* Offloads for IPv4 */
        ip4->hdr_checksum = 0;
        c->l2_len = l2_len;
        c->l3_len = ihl_bytes;
        c->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;

        if (l4_proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
            tcp->cksum = 0;
            c->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
        } else if (l4_proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
            udp->dgram_cksum = 0;
            c->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        }
        return 0;
    }
    else if (etype == RTE_ETHER_TYPE_IPV6) {
        if (pkt_len < off + sizeof(struct rte_ipv6_hdr)) return -1;
        struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)((uint8_t *)eth + off);

        /* Find L4 start (walk extension headers) */
        if (ipv6_find_l4(ip6, pkt_end, &l4_proto, &l4_ptr) != 0)
            return -1;

        /* Extract ports if TCP/UDP */
        uint16_t sport_be = 0, dport_be = 0;
        if (l4_proto == IPPROTO_TCP) {
            if (l4_ptr + sizeof(struct rte_tcp_hdr) > pkt_end) return -1;
            const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)l4_ptr;
            sport_be = tcp->src_port; dport_be = tcp->dst_port;
        } else if (l4_proto == IPPROTO_UDP) {
            if (l4_ptr + sizeof(struct rte_udp_hdr) > pkt_end) return -1;
            const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)l4_ptr;
            sport_be = udp->src_port; dport_be = udp->dst_port;
        } else {
            // printf("Unsupported v6 L4 proto %u\n", l4_proto);
            return -1;
        }

        /* Build IPv6 key (ports are BE16) */
        ft_key_from_ipv6(&key, &ip6->src_addr, &ip6->dst_addr, sport_be, dport_be, l4_proto);

        /* Lookup action */
        const struct ft_action *act = ft_lookup(ft, &key);
        switch (act->kind) {
        case FT_ACT_NOP:
            break;
        case FT_ACT_DROP:
            return -2;

        case FT_ACT_REWRITE_L2:
        case FT_ACT_REWRITE_L2L3:
        case FT_ACT_REWRITE_L2L3L4:
            if (act->src_mac_valid) eth->src_addr = act->new_src_mac;
            if (act->dst_mac_valid) eth->dst_addr = act->new_dst_mac;
            if (act->kind == FT_ACT_REWRITE_L2) break;
            /* FALLTHROUGH: L3 for IPv6 not implemented with current ft_action fields */
            /* If you add IPv6 fields to ft_action, do the ip6 src/dst rewrite here. */
            if (act->kind == FT_ACT_REWRITE_L2L3) break;
            /* fallthrough to L4 */

        case FT_ACT_REWRITE_L3:
        case FT_ACT_REWRITE_L3L4:
        case FT_ACT_REWRITE_L4: {
            if (l4_proto == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
                if (act->sport_valid) tcp->src_port = act->new_sport;
                if (act->dport_valid) tcp->dst_port = act->new_dport;
            } else if (l4_proto == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
                if (act->sport_valid) udp->src_port = act->new_sport;
                if (act->dport_valid) udp->dst_port = act->new_dport;
            }
            break;
        }
        default:
            break;
        }

        /* Offloads for IPv6:
         * - No L3 checksum; set IPv6 flag and l3_len = sizeof(ipv6)
         * - L4 pseudo-header checksum is computed by HW with TCP/UDP flags
         */
        c->l2_len = l2_len;
        c->l3_len = sizeof(struct rte_ipv6_hdr);
        c->ol_flags |= RTE_MBUF_F_TX_IPV6;

        if (l4_proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
            tcp->cksum = 0;
            c->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
        } else if (l4_proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
            udp->dgram_cksum = 0;
            c->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        }
        return 0;
    }

    /* Non-IP */
    return -1;
}


/* Primary buffer filler process when running in dynamic expansion mode. In this configuration all worker threads read the same common 
   mbuf array in sequence. for each packet each worker thread manages a number of "virtual" flows. virtual flows are the same exact packet 
   sequence from the master mbuf array (with timing preserved) but with a target IP address replaced with a virtual IP. This allows a small sequence of 
   pcaps to expand into a higher bandwidth, high connection rate, high concurrent connection replay with the same underlying protocol and timing characteristics
   
   virtial flows are intialized with a uniformly random start time offset (relative to the pcap file length).*/


static __rte_always_inline int process_dyn_expansion(struct flow_table *ft, struct pcap_mbuff_slot pcap_buffer, struct rte_ring *tx_ring, 
    unsigned int *cur_index, struct rte_mempool *clonepool, int64_t current_time, int tsp_offset, int64_t *start_time,
    uint32_t core_id, uint32_t vert_id){
    
    int j =0;
    struct rte_mbuf *clones[RING_BURST];
    unsigned int cnt = pcap_buffer.mbuf_array[0].count;
    int64_t pkt_time = 0;
    
    /* iterate over pcap buffer indexed by the slot assignment, pick up where we last left off with this port via 
       pcap_cur_index we maintain for each port */
    for(j=*cur_index; j < cnt;j++){

        //set the burst size either to RING_BURST or whatever the remaining number of packets is 
        //in this mode this is the max we could enqueue, but we will only queue packets with the right timestamp
        unsigned int remaining = cnt - j;
        uint16_t burst_cnt = (remaining < RING_BURST) ? remaining : RING_BURST;
        
        //clone next RING_BURST amount of cloned packets 
        //guard creation loop, check for clone failures and bail and flag if clone failures occured
        uint16_t created = 0;
        for (int i=0; i < burst_cnt; i++) {
            
            //get timestamp of packet
            pkt_time = (int64_t)my_ts_get(pcap_buffer.mbuf_array[0].pkts[j+created], tsp_offset);  
            
            //only clone and add packet it the timestamp is <= the current sequence time
            if (current_time >= pkt_time){
                struct rte_mbuf *tmpl = pcap_buffer.mbuf_array[0].pkts[j + created];

                // Sanity: template must be direct, immutable, refcnt==1
                RTE_ASSERT(!RTE_MBUF_INDIRECT(tmpl));
                RTE_ASSERT(rte_mbuf_refcnt_read(tmpl) == 1);

                struct rte_mbuf *c = rte_pktmbuf_copy(tmpl, clonepool,0,UINT32_MAX);
                if (unlikely(c == NULL)) {
                    printf("failed to clone\n");
                    break; // pool pressure: just send the ones we cloned
                }

                int rc = modify_mbufclone_hdrs(ft,c,core_id,vert_id);
                
                //if drop, skip
                if (rc == -2){
                    continue;
                }
                clones[created] = c;
                created++;
            }
            else {
                break;
            }
        }
        if (created == 0) {
            // Nothing cloned right now; yield a bit and retry next call
            rte_pause();
            break;
        }
        //add to rx_ring
        // multi-producer enqueue; try burst, if ring is full re-try, we want to backpressure 
        uint16_t enqueued = 0;
        uint16_t tx_n = 0;
        int waiting = 0;
        while (enqueued < created) {
            tx_n = rte_ring_mp_enqueue_burst(tx_ring, (void * const*)(clones+enqueued), created-enqueued, NULL);
            rte_pause();
            enqueued += tx_n;
            waiting++;
        }

        //increment j (pcap packet index) but number of packets we've processed
        j+=created;
        
        //check if we actually could create a full burst, if not we hit a time limit and bail
        if(created < burst_cnt){
            break;
        }
    }

    // if we've reached the end of the pcap array, reset and process first chunk
    if (j >= cnt){
        //printf("reseting\n");
        *cur_index = 0; 
        *start_time = rte_rdtsc();
    }  
    else{
        *cur_index = j % cnt; 
    }
    
    return 0;
}

/* Main entry point for buffer filler worker DPDK thread 
takes pointer to the buff_worker_args struct as the main argument 
    -buffer worker threads fall into a infinite loop, servicing pcap memory slots assigned on a per port and tx/buff core pair basis 
    -each buffer worker produces data for exactly on TX core, with N double buffer pairs where N is number of configured ports. 
    -Multiple buffer threads can source data for a single tx core, a global sequence ID, per buffer offset, and total group sizing used to maintain order
Multiple 
*/
int buffer_worker(__rte_unused void *arg) {

    //extract thread args 
    struct buff_worker_args *buff_args = (struct buff_worker_args *)arg;
    unsigned int tsp_offset = buff_args->global_state->mbuf_ts_off;

    //figure out core configuration 
    unsigned int lcore_id = rte_lcore_id();                     // who am I?
    unsigned int tx_core_index = buff_args->linked_tx_core;     // what tx core am I linked to?

    //some helper variables for managing reading pcap packets from pcap storage
    struct pcap_mbuff_slot  pcap_buffer[buff_args->num_ports];   
    int pcap_size_len[buff_args->num_ports];      
    int slot_assignment[buff_args->num_ports];   
    int slot_assignment_r2[buff_args->num_ports];   
    int port_enabled[buff_args->num_ports];   
    int port_enabled_r2[buff_args->num_ports];   
    int cntr = 0;

    //some helper variables to manage double buffer API structs that link buffer filler to tx core 
    //each variable is an array of [buff_args->num_tx_buffs] (number of configured ports), since there is a separate 
    //pcap slot assigned and double buffer array to communicate separate packet streams per port per buff/tx core pair 
    unsigned int            pcap_cur_index[buff_args->num_ports];  //track latest base index on a per tx double buff basis (1x per port)

    //get a pointer to the clone pools used for creating mbuf clones (one pool per tx thread)
    //buffer fillers create clones in their target tx cores clone mempool
    struct rte_mempool      *clonepool = buff_args->clone_mpool;     
    uint64_t tsc_hz = rte_get_tsc_hz();
    printf("tsc_hz: %lu\n",tsc_hz);

    printf("\n--------------------- Buffer Lcore %d --------------------------\n", lcore_id);
    printf("Lcore_%d - Starting Buffer Filler Thread\n", lcore_id);
    printf("Lcore_%d - Total Configured Output Buffers (1x per Port) %d\n",lcore_id,buff_args->num_ports);  
    printf("Lcore_%d - Linked Tx Core: %d\n", lcore_id, buff_args->linked_tx_core);

    //initialize per tx (port) instance double buffer variables
    for (int i =0; i < buff_args->num_ports; i++){
        pcap_cur_index[i]       = 0;
        slot_assignment[i]      = -1;
        slot_assignment_r2[i]   = -1;
        port_enabled[i]         = 0;
        port_enabled_r2[i]      = 0;
    }

    //initialize flowtable reader 
    ft_reader_init(buff_args->global_flowtable, buff_args->buff_thread_index);
    
    /* Main Thread Loop - Run till killed */
    for(;;){
        /* for each configured port */
        for (int i =0; i< buff_args->num_ports; i++){   
                
            /* PCAP mbuf arrays are indexed by "slotid". In order to transmit a pcap, a tx core's slot assignment has to be populated 
               there is a separate slot assignment for each port + tx core combo */
            slot_assignment[i] = buff_args->global_state->pcap_storage_t->slot_assignments[i][tx_core_index];
            
            //if slot assignment is new
            if(slot_assignment[i] != slot_assignment_r2[i]){
                slot_assignment_r2[i] = slot_assignment[i];

                //pre-process virtual flow array, initializes all vert flows
                for(int j =0;j < buff_args->virt_ip_cnt;j++){
                    buff_args->virtual_flows[i][j].tx_pkt_index = 0; 
                    buff_args->virtual_flows[i][j].running = false;
                    buff_args->virtual_flows[i][j].offset_ns = rand_u64_uniform(buff_args->global_state->pcap_storage_t->slots[slot_assignment[i]].delta_ns);
                }
            }

            //ports are enabled or disabled at a global level, all cores see and check these flags
            port_enabled[i] = buff_args->global_state->port_enable[i];
            //detect disable -> enable transition 
            if (port_enabled[i] == 1 && port_enabled_r2[i] == 0){
                uint64_t start = rte_rdtsc();
                for(int j =0;j < buff_args->virt_ip_cnt;j++){
                    buff_args->virtual_flows[i][j].start_time_ns = (int64_t)start;
                }

                port_enabled_r2[i] = 1;
            }
            //detect enable -> disable transition 
            else if (port_enabled[i] == 0 && port_enabled_r2[i] == 1){
                for(int j =0;j < buff_args->virt_ip_cnt;j++){
                    buff_args->virtual_flows[i][j].tx_pkt_index = 0;
                    buff_args->virtual_flows[i][j].start_time_ns = 0;
                    buff_args->virtual_flows[i][j].running = false;
                }
                port_enabled_r2[i] = 0;
            }

            //if port slot doesn't have a pcap slot assigned, or port not enabled skip so we can start to proces the next port in the series (if configured)
            if(slot_assignment[i] == -1 || port_enabled[i] == 0)
                continue;

            //get pcap slot pointer 
            pcap_buffer[i] = buff_args->global_state->pcap_storage_t->slots[slot_assignment[i]];

            //get pcap size 
            pcap_size_len[i] = buff_args->global_state->pcap_storage_t->slots[slot_assignment[i]].numpackets;

            //get replay mode 
            pcap_replay_t mode = buff_args->global_state->pcap_storage_t->slots[slot_assignment[i]].mode;

            //if pcap has content, process it 
            if((pcap_size_len[i] > 0)){

                //direct replay, grouped buffer threads interate in chunks replaying packets in sequence to tx cores
                if (mode == REPLAY_DIRECT){
                    process_direct_replay(pcap_buffer[i],buff_args->buffer_rings[i],&pcap_cur_index[i],PCAP_READ_CHUNK,clonepool);
                }


                //dynamic flow expansion, each buffer thread handles its own N clones of the overall sequence 
                else if (mode == DYN_EXPAND){
                    
                    //iterate over all enabled virtual channels
                    for (int j=0; j < buff_args->global_state->virt_channels_per_port[i];j++){
                        unsigned int *virt_pkt_index = &buff_args->virtual_flows[i][j].tx_pkt_index;

                        int64_t offset_time = ((((int64_t)rte_rdtsc() - buff_args->virtual_flows[i][j].start_time_ns)*1e9) / (double)tsc_hz);
                        if (buff_args->virtual_flows[i][j].running == false){
                            //get current time (relative to overall pcap time), each virtual channel has a separate offset and "current time" tracker 
                            offset_time = offset_time - buff_args->virtual_flows[i][j].offset_ns;
                        }

                        if (offset_time >= 0){
                            buff_args->virtual_flows[i][j].running = true;
                        }
                        
                        //if negative (we've not hit the start offset yet) pass it along unmodified, 
                        //negative values will cause the send logic to skip
                        buff_args->virtual_flows[i][j].cur_time_ns = offset_time;
                        
                        process_dyn_expansion(buff_args->global_flowtable, pcap_buffer[i], buff_args->buffer_rings[i],virt_pkt_index, clonepool, 
                            buff_args->virtual_flows[i][j].cur_time_ns, tsp_offset,&buff_args->virtual_flows[i][j].start_time_ns,buff_args->buff_thread_index,j);
    
                        cntr++;
                        if (buff_args->global_state->port_enable[i] == 0){
                            break;
                        }
                    }
                }
                
            } 
        }
        
        //mark thread as idle for flowtable background tasks 
        ft_reader_idle(buff_args->global_flowtable, buff_args->buff_thread_index);
    }
    
    return 0;
}