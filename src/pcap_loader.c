/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: pcap_loader.c 
Description: Primary entry point and supporting code for the pcap_loader pthread. The pcap loader thread 
is launched by the main DPDK application and waits for commands to be received via a shared memory 
pcap_loader_ctl struct. When signaled to start, the pcap loader thread calls pcap processing functions 
to load the pcap file into a dynamically sized pcap storage array indexed by slotid. After loading pcap files into 
pcap file storage, other threads (the control server mostly) can assign pcap slot id's to each tx core / buffer thread groups 
for transmission. 
*/

#include <pcap/pcap.h>             
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>   // if your version has it
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "pcap_loader.h"
#include "app_defines.h"
#include "mbuf_fields.h"


/* ------------------------------- dynamic mbuff array functions --------------------------*/
//init a dynamically resizing mbuff array struct 
static void mbuf_array_init(struct mbuf_array *arr) {
    arr->pkts = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

//add an mbuff to an array and resize if needed
static void mbuf_array_push(struct mbuf_array *arr, struct rte_mbuf *m) {
    if (arr->count == arr->capacity) {
        size_t newcap = (arr->capacity == 0) ? 16 : arr->capacity * 2;
        struct rte_mbuf **newpkts = realloc(arr->pkts, newcap * sizeof(*newpkts));
        if (!newpkts) {
            perror("realloc failed");
            exit(EXIT_FAILURE);
        }
        arr->pkts = newpkts;
        arr->capacity = newcap;
    }
    arr->pkts[arr->count++] = m;
}

//free mbuff array
static void mbuf_array_free(struct mbuf_array *arr) {
    for (size_t i = 0; i < arr->count; i++) {
        if (arr->pkts[i])
            rte_pktmbuf_free(arr->pkts[i]);
    }
    free(arr->pkts);
    arr->pkts = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

/* ------------------------------- dynamic pcap storage array functions --------------------------*/
//Initialize pcap storage struct
static void pcap_storage_init(struct pcap_storage *st) {
    st->slots = NULL;
    st->count = 0;
    st->capacity = 0;
}

//add a new mbuff array (parsed pcap) to the storage structure 
static void pcap_storage_add(struct pcap_storage *st, 
    struct mbuf_array *mbuffs, 
    unsigned int numpackets, 
    const char *pcap_name, 
    unsigned int *slot,
    uint64_t start_ns, 
    uint64_t end_ns,
    uint64_t total_bytes) {

    if (st->count == st->capacity) {
        size_t newcap = (st->capacity == 0) ? 4 : st->capacity * 2;
        struct pcap_mbuff_slot *newslots = realloc(st->slots, newcap * sizeof(struct pcap_mbuff_slot));
        if (!newslots) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        st->slots = newslots;
        st->capacity = newcap;
    }

    //populate pcap struct
    snprintf(st->slots[st->count].pcap_name, sizeof(st->slots[st->count].pcap_name), "%s", pcap_name);
    st->slots[st->count].numpackets = numpackets;
    st->slots[st->count].mbuf_array = mbuffs;
    st->slots[st->count].start_ns = start_ns;
    st->slots[st->count].end_ns = end_ns;
    st->slots[st->count].delta_ns = end_ns-start_ns;
    st->slots[st->count].size_in_bytes = total_bytes;
    st->slots[st->count].mode = UNASSIGNED;

    *slot = st->count;

    st->count++;
}

//free pcap storage array 
static void pcap_storage_free(struct pcap_storage *st) {
    for (size_t i = 0; i < st->count; i++) {
        struct pcap_mbuff_slot *slot = &st->slots[i];
        mbuf_array_free(slot->mbuf_array);
        //free packet array
        free(slot->mbuf_array);
    }
    free(st->slots); 
    st->slots = NULL;
    st->count = 0;
    st->capacity = 0;
}

/* -------------------------------------------- Primary Pcap Loading / Processing Functions -----------------------------------*/

//function to copy raw packet bytes into mbuffs, handles cases where packet must be split across chained mbuffs (jumbo's)
static inline int append_bytes_to_mbuf(struct rte_mbuf **pmbuf, struct rte_mempool *mp, const uint8_t *src, uint32_t len)
{
    struct rte_mbuf *m = *pmbuf;
    uint32_t remaining = len;

    //while we still have bytes to process from the pcap packet
    while (remaining) {

        // How many bytes fit in the current last segment?
        struct rte_mbuf *last = rte_pktmbuf_lastseg(m);
        uint32_t tailroom = rte_pktmbuf_tailroom(last);

        if (tailroom == 0) {
            // Need a new segment
            struct rte_mbuf *seg = rte_pktmbuf_alloc(mp);
            if (!seg) return -ENOMEM;
            seg->next = NULL;
            seg->data_len = 0;
            last->next = seg;
            m->nb_segs++;
            last = seg;
            tailroom = rte_pktmbuf_tailroom(last);
        }

        uint32_t to_copy = remaining < tailroom ? remaining : tailroom;
        uint8_t *dst = rte_pktmbuf_mtod_offset(last, uint8_t *, last->data_len);
        rte_memcpy(dst, src + (len - remaining), to_copy);
        last->data_len += to_copy;
        m->pkt_len   += to_copy;
        remaining    -= to_copy;
    }

    return 0;
}

static uint64_t ts_to_ns(const struct pcap_pkthdr *h, int prec) {
    // prec is PCAP_TSTAMP_PRECISION_MICRO or PCAP_TSTAMP_PRECISION_NANO
    uint64_t sec_ns = (uint64_t)h->ts.tv_sec * 1000000000ull;
    uint64_t sub    = (prec == PCAP_TSTAMP_PRECISION_NANO)
                        ? (uint64_t)h->ts.tv_usec               // tv_usec holds ns in nano mode
                        : (uint64_t)h->ts.tv_usec * 1000ull;    // micro -> nano
    return sec_ns + sub;
}


//main pcap processing function, takes a filename and core assignment and perform the read and conversion into mbuf's 
static int process_pcap(struct pthread_args *thread_args, const char *filename){
    const uint8_t *data;
    struct pcap_pkthdr *hdr;
    int rc;
    uint64_t first_ns = 0, last_ns = 0;
    uint64_t total_bytes =0; 

    //all pcaps stored in mbuffs from the pcap template mempool
    struct rte_mempool *mp = thread_args->global_state->pcap_template_mpool; 

    //init dynamically resizeable array
    struct mbuf_array *mbuff_array = calloc(1, sizeof(struct mbuf_array));
    mbuf_array_init(mbuff_array);
    

    //open file with libpcap
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; 
    // Try to open with nanosecond precision; fall back to default (microseconds)
    pcap_t *pc = pcap_open_offline_with_tstamp_precision(filename, PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!pc) {
        pc = pcap_open_offline(filename, errbuf);
        if (!pc) { fprintf(stderr, "pcap open failed: %s\n", errbuf); return 1; }
    }
    //get actual precision
    int prec = pcap_get_tstamp_precision(pc); // MICRO or NANO


    //check and enforce ethernet only
    int dlt = pcap_datalink(pc);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type (DLT=%d). Expected DLT_EN10MB.\n", dlt);
        pcap_close(pc);
        return -ENOTSUP;
    }

    bool have_first = false;
    //while we still have pcap frames to process
    while ((rc = pcap_next_ex(pc, &hdr, &data)) >= 0) {
        if (rc == 0) continue; // timeout (pcapng live only; with files usually not seen)
        
        //keep track of time in ns
        uint64_t ns = ts_to_ns(hdr, prec);
        if (!have_first) { 
            first_ns = ns; 
            have_first = true; 
        }
        last_ns = ns;   // "last in file"

        const uint32_t caplen = hdr->caplen; // bytes captured
        total_bytes = total_bytes + caplen;
        // const uint32_t plen = hdr->len;   // original length on wire (can differ)

        //create a mbuff to hold the pcap
        struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
        if (!m) {
            fprintf(stderr, "mbuf alloc failed (rte_errno=%d)\n", rte_errno);
            pcap_close(pc);
            return -ENOMEM;
        }

        //init mbuff header
        m->data_len = 0;
        m->pkt_len  = 0;
        m->nb_segs  = 1;
        m->next     = NULL;

        my_ts_set(m,thread_args->global_state->mbuf_ts_off,ns-first_ns);

        // Copy payload into mbuf, auto chain for jumbo
        if (append_bytes_to_mbuf(&m, mp, data, caplen) != 0) {
            rte_pktmbuf_free(m);
            pcap_close(pc);
            return -ENOMEM;
        }
        
        //add mbuff to mbuff array 
        mbuf_array_push(mbuff_array,m);

    }
    

    //push mbuff array into global pcap storage struct
    pcap_storage_add(thread_args->global_state->pcap_storage_t, 
        mbuff_array, mbuff_array->count, 
        filename, 
        &thread_args->pcap_controller->latest_slotid,
        first_ns, 
        last_ns,
        total_bytes);

    return 0;
}

/* Main thread called by control_server thread to load and pre-process pcap files if */
void *run_pcap_loader_thread(void *arg) {
    struct pthread_args *thread_args  = (struct pthread_args *)arg;
    struct pcap_loader_ctl * ctl = thread_args->pcap_controller;

    //initialize storage structs 
    pcap_storage_init(thread_args->global_state->pcap_storage_t);

    //initialize lock when thread launches
    pthread_mutex_lock(&ctl->lock);

    while (1) {
        // Wait for a command, use cond_wait so we don't have to poll 
        while (ctl->command == CMD_NONE) {
            pthread_cond_wait(&ctl->cond, &ctl->lock);
        }

        // process commands
        if (ctl->command == CMD_EXIT) {
            pthread_mutex_unlock(&ctl->lock);
            break;
        }

        if (ctl->command == CMD_LOAD_PCAP) {
            ctl->busy = true;
            
            //copy filename over so we can release the lock while loading
            char file[256];
            snprintf(file, sizeof(file), "%s", ctl->filename);
            
            //clear command 
            ctl->command = CMD_NONE;
            
            //unlock struct now that we know the file and can load it
            pthread_mutex_unlock(&ctl->lock);

            //process pcap file
            int rc = process_pcap(thread_args,file);


            pthread_mutex_lock(&ctl->lock);
            ctl->result = rc;
            ctl->busy = false;
        }
    }

    pcap_storage_free(thread_args->global_state->pcap_storage_t);
    return NULL;
}
