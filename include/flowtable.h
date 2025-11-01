#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
#include <rte_hash.h>
#include <stdbool.h>
#include <rte_rcu_qsbr.h>
#include <rte_ether.h>
#include <rte_per_lcore.h> 

#define L1_SIZE 64 /* per-lcore tiny cache */

/* Intel default Toeplitz RSS key (40 bytes) */
static const uint8_t default_rss_key[40] = {
    0x6D, 0x5A, 0x56, 0xDA,
    0x25, 0x5B, 0x0E, 0xC2,
    0x41, 0x67, 0x25, 0x3D,
    0x43, 0xA3, 0x8F, 0xB0,
    0xD0, 0xCA, 0x2B, 0xCB,
    0xAE, 0x7B, 0x30, 0xB4,
    0x77, 0xCB, 0x2D, 0xA3,
    0x80, 0x30, 0xF2, 0x0C,
    0x6A, 0x42, 0xB7, 0x3B,
    0xBE, 0xAC, 0x01, 0xFA
};

/* ---------- Key / Value model (unified v4/v6) ---------- */
enum ft_ipver {
    FT_IPV4 = 4,
    FT_IPV6 = 6
};

/* Fixed-size, memcmp-able 5-tuple:
 * - family: 4 or 6
 * - src/dst: 16 bytes each (IPv4 goes in last 4 bytes as v4-mapped-style or placed in lower bytes; we just standardize)
 * - ports: network order (BE16)
 * - proto: IP protocol number (e.g., TCP=6, UDP=17)
 *
 * Layout is chosen so rte_hash can compare bytes directly.
 */
struct flow5 {
    uint8_t  family;     // FT_IPV4 or FT_IPV6
    uint8_t  proto;      // IP protocol 
    uint16_t _pad0;      // align to 32-bit for stable hashing/memcmp
    uint8_t  src[16];    // network-order bytes; for IPv4, store at bytes [12..15]
    uint8_t  dst[16];    // same
    uint16_t src_port;   // BE16
    uint16_t dst_port;   // BE16
} __attribute__((packed));
 
/* ---------- enum for hash type -------------------*/
enum ft_hash_type {
    FT_HASH_CRC32 = 0,
    FT_HASH_RSS
};

/* ---------- enum for supported actions - per flow packet modifications ---------- */
enum ft_action_kind {
    FT_ACT_NOP = 0, 
    FT_ACT_DROP, 
    FT_ACT_REWRITE_L2, 
    FT_ACT_REWRITE_L3,
    FT_ACT_REWRITE_L4,
    FT_ACT_REWRITE_L2L3, 
    FT_ACT_REWRITE_L3L4,
    FT_ACT_REWRITE_L2L3L4
};

/* ---------- struct for holding action information ---------- */
struct ft_action {
    enum ft_action_kind kind;
    struct rte_ether_addr new_dst_mac;
    struct rte_ether_addr new_src_mac; 
    uint32_t new_src_ip_subnet;
    uint32_t new_dst_ip_subnet;
    uint16_t new_sport;
    uint16_t new_dport;
    bool dst_mac_valid, src_mac_valid, dst_ip_valid, src_ip_valid, sport_valid, dport_valid;
    bool default_rule;
}__rte_cache_aligned;

// indirect action pointer handle for atomic updates
struct indr_action_handle {
    _Atomic(struct ft_action *) ptr;
};

/* ---------- Flowtable Config / Handle ---------- */
struct ft_cfg {
    const char *name;
    uint32_t entries;          /* expected max flows (size hint) */
    int socket_id;
    int shards;               /* 1, 2, 4, 8… (power of two); use >1 to reduce metadata contention */
    int num_reader_threads;
    enum ft_hash_type hash_algo;
    const struct ft_action *default_action; /* must be non-NULL & long-lived */

    int qsbr_reclaim_limit;
    int qsbr_max_reclaim_size;
};


/* ---------- struct for holding small L1 cache per lcore of action information ---------- */
struct l1e { 
    struct flow5 key; 
    struct indr_action_handle *h; 
};
//per lcore key/action pair caches 
RTE_DECLARE_PER_LCORE(struct l1e, l1)[L1_SIZE];

/* ---------- Struct to support sharding of hash table if lcores are working on flow aware input queues ---------- */
struct shard {
    char name[64];
    struct rte_hash *h;
} __rte_cache_aligned;

/* ---------- Struct for main flow table access and confguration ---------- */
struct flow_table {
    struct ft_cfg cfg;
    int shards;
    struct shard *s; /* [shards] */    
    //qsbr manager struct 
    struct rte_rcu_qsbr *qs;
    struct rte_rcu_qsbr_dq *dq;
};

/* ---------- Lifecycle ---------- */
struct flow_table *ft_create(const struct ft_cfg *cfg);
void ft_destroy(struct flow_table *ft);
void ft_reader_init(struct flow_table *ft, int thread_id);
void ft_reader_idle(struct flow_table *ft, int thread_id);

/* ---------- Lookups (fast path) ---------- */
const struct ft_action *ft_lookup(const struct flow_table *ft, const struct flow5 *key);
const struct ft_action *ft_lookup_prehash(const struct flow_table *ft, const struct flow5 *key, uint32_t sig);

/* ---------- Updates (control-plane) ---------- */
/* Insert: returns 0 on insert; -EEXIST if already present */
int ft_add(struct flow_table *ft, const struct flow5 *key, const struct ft_action *act);
int ft_append(struct flow_table *ft, const struct flow5 *k, const struct ft_action *init_a);

/* Upsert: replace or add; returns 0, sets *old_act if replaced (may be NULL). */
int ft_replace(struct flow_table *ft, const struct flow5 *key, const struct ft_action *new_act,struct ft_action **old_act);

/* Delete: returns 0 if removed; -ENOENT if missing. */
int ft_del(struct flow_table *ft, const struct flow5 *key);

/* ---------- Helpers to build keys ---------- */
static inline void ft_key_from_ipv4(struct flow5 *k, uint32_t src_be, uint32_t dst_be,
                                    uint16_t sport_be, uint16_t dport_be, uint8_t proto)
{
    memset(k, 0, sizeof(*k));
    k->family = FT_IPV4;
    k->proto  = proto;
    /* Place v4 into last 4 bytes (RFC4291 v4-mapped layout style, though we don’t mark ::ffff) */
    memcpy(&k->src[12], &src_be, 4);
    memcpy(&k->dst[12], &dst_be, 4);
    k->src_port = sport_be;
    k->dst_port = dport_be;
}

static inline void ft_key_from_ipv6(struct flow5 *k, const void *src16, const void *dst16,
                                    uint16_t sport_be, uint16_t dport_be, uint8_t proto)
{
    k->family = FT_IPV6;
    k->proto  = proto;
    memcpy(k->src, src16, 16);
    memcpy(k->dst, dst16, 16);
    k->src_port = sport_be;
    k->dst_port = dport_be;
}

#endif
