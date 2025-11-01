#include "flowtable.h"
#include <rte_hash_crc.h>
#include <rte_thash.h>
#include <rte_malloc.h>
#include <rte_per_lcore.h> 
#include <rte_lcore.h> 
#include <string.h>
#include <stdatomic.h>

//per lcore key/action pair caches 
RTE_DEFINE_PER_LCORE(struct l1e, l1)[L1_SIZE];


/* ------------------------------ Configuration and Init functions --------------------------------------------*/
/* callback function for freeing a retired action object, used when calling rte_rcu_qsbr_dq_reclaim by the ft manager */
static void ft_free_action_cb(void *arg, void *entries, unsigned int n)
{
    (void)arg; // optional context, ignore if unused
    void **arr = (void **)entries;   // array of pointers, n elements
    for (unsigned int i = 0; i < n; i++) {
        // We enqueue both action* and handle*; both were rte_zmalloc'd
        rte_free(arr[i]);
    }
}

// Function to round a number to a power of 2
static inline uint32_t pow2_ceiling(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1; x |= x >> 2; x |= x >> 4; x |= x >> 8; x |= x >> 16;
    return x + 1;
}

/* ---- internal function for creating the rte_hash datastructure ----- */
static struct rte_hash *make_hash(const char *name, int socket_id, uint32_t entries) {
    
    //create re_hash_parameters strcuture, currently configured for maximum thread safe behavior (see below)
    struct rte_hash_parameters hp = {
        .name = name, 
        .entries = entries, 
        .key_len = sizeof(struct flow5),
        .socket_id = socket_id,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE       |   //we are storing data along side keys 
                      RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | //readers/writers can opearte on the hash table simultaniously 
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD    //allow multiple writes to safeuly add keys simultaniously 
    };

    //return a pointer to the rte_hash structure created with the config above
    return rte_hash_create(&hp);
}


/* ---- External function for creating the main hash table structure ----- */
struct flow_table *ft_create(const struct ft_cfg *cfg) {
    
    int rc = 0;
    //use rte_zmalloc to reserve flowtable memory pointer, use rte zmalloc to allow use of dpdk managed memory 
    struct flow_table *ft = rte_zmalloc_socket(cfg->name, sizeof(*ft), RTE_CACHE_LINE_SIZE, cfg->socket_id);
    
    ft->cfg = *cfg;
    ft->shards = cfg->shards > 0 ? pow2_ceiling(cfg->shards) : 1; //enforce a minimum of one shard  stripe 
    ft->s = rte_zmalloc_socket("ft_shards", sizeof(struct shard)*ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    if (!ft->s) 
        goto fail_ft;

    //create the hashtable structure and assign it to each shard
    for (int i=0;i<ft->shards;i++){
        char n[64]; 
        snprintf(n,sizeof n,"%s_%d",cfg->name,i);
        uint32_t per = RTE_MAX(1u, cfg->entries / ft->shards);
        
        snprintf(ft->s[i].name,sizeof (ft->s[i].name),"%s_%d",cfg->name,i);
        ft->s[i].h = make_hash(n, cfg->socket_id, per);
        //if failure occurs
        if (!ft->s[i].h) {
            // unwind already-created shards
            for (int j = 0; j < i; j++) {
                rte_hash_free(ft->s[j].h);
            }
            goto fail_shards;
        }
    }

    //create qsbr structures and initialize differ queue  
    size_t qs_size = rte_rcu_qsbr_get_memsize(cfg->num_reader_threads);
    ft->qs = rte_zmalloc(NULL, qs_size, RTE_CACHE_LINE_SIZE);
    if (!ft->qs){
        for (int i = 0; i < ft->shards; i++) rte_hash_free(ft->s[i].h);
        goto fail_shards;
    }

    rc = rte_rcu_qsbr_init(ft->qs, cfg->num_reader_threads);
    if (rc != 0) {
        // free hashes
        for (int i = 0; i < ft->shards; i++) rte_hash_free(ft->s[i].h);
        goto fail_shards;
    }

    ft->dq = rte_rcu_qsbr_dq_create(&(struct rte_rcu_qsbr_dq_parameters){
        .name = "ft_dq",
        .v = ft->qs,
        .size = 65536,
        .esize = sizeof(void *),
        .free_fn = ft_free_action_cb,      // action retire free function
        .trigger_reclaim_limit = cfg->qsbr_reclaim_limit,     // start reclaim when queue reaches this
        .max_reclaim_size = cfg->qsbr_max_reclaim_size,          // max items freed per reclaim call
    });
    if (!ft->dq) {
        printf("in dq failure\n");
        for (int i = 0; i < ft->shards; i++) rte_hash_free(ft->s[i].h);
        rte_free(ft->qs);
        goto fail_shards;
    }

    //return flowtable pointer
    return ft;

fail_shards:
    rte_free(ft->s);
fail_ft:
    rte_free(ft);
    return NULL;
}


/* ---- External function for cleanly removing the flowtable structures ----- */
void ft_destroy(struct flow_table *ft) {
    
    //for each shard, call rte_hash_free on it's hashtable struct
    for (int i=0;i<ft->shards;i++){ 
        rte_hash_free(ft->s[i].h);
    }

    //reclaim all outstanding retired actions
    rte_rcu_qsbr_synchronize(ft->qs, RTE_QSBR_THRID_INVALID); // wait for readers
    unsigned int freed = 0, pending= 0, avail = 0;
    do {
        rte_rcu_qsbr_dq_reclaim(ft->dq, 0, &freed, &pending, &avail);
    } while (pending);
    
    //free the qsbr sq structs 
    rte_free(ft->qs);

    //free the qsbr differ queue
    rte_rcu_qsbr_dq_delete(ft->dq);    
    
    //free the shard array pointer
    rte_free(ft->s); 

    //free the flowtable pointer 
    rte_free(ft);
}


/* ---- External function for reader threads to register to the QSBR struct ----- */
void ft_reader_init(struct flow_table *ft, int thread_id){
    rte_rcu_qsbr_thread_register(ft->qs, thread_id);
    rte_rcu_qsbr_thread_online(ft->qs, thread_id);   
}


/* ------------------------------ Lookup Functions used by reader cores --------------------------------------------*/

/* ---- Internal function for calculating which shard to index into given a signature hash ----- */
static inline uint32_t shard_id(const struct flow_table *ft, uint32_t sig) {
    //shard index comes from the lowest bits of the signature, depends on number of total shards
    return (sig & (ft->shards - 1));
}

/* ---------------- RSS helpers ---------------- */

/* IPv4 soft-RSS on 5-tuple (be32 words) */
static inline uint32_t rss_hash_v4(const struct flow5 *k, const uint8_t *rss_key)
{
    /* src/dst are in last 4 bytes of 16-byte arrays */
    uint32_t be_src, be_dst;
    memcpy(&be_src, &k->src[12], 4);
    memcpy(&be_dst, &k->dst[12], 4);

    uint32_t be_words[4];
    be_words[0] = be_src;                          // already BE32
    be_words[1] = be_dst;                          // already BE32
    uint32_t ports = ((uint32_t)k->src_port << 16) | (uint32_t)k->dst_port; // both BE16
    be_words[2] = rte_cpu_to_be_32(ports);
    be_words[3] = rte_cpu_to_be_32((uint32_t)k->proto << 24);
    return rte_softrss_be(be_words, 4, rss_key);
}

/* IPv6 soft-RSS on 5-tuple: 16+16 + ports + proto = 37 bytes -> 10 be32 words (last padded) */
static inline uint32_t rss_hash_v6(const struct flow5 *k, const uint8_t *rss_key)
{
    uint32_t w[10];

    /* src[0..15] as 4x be32 */
    for (int i = 0; i < 4; i++) {
        uint32_t tmp;
        memcpy(&tmp, &k->src[i*4], 4);
        w[i] = tmp; // bytes are already in network order
    }
    /* dst[0..15] as 4x be32 */
    for (int i = 0; i < 4; i++) {
        uint32_t tmp;
        memcpy(&tmp, &k->dst[i*4], 4);
        w[4+i] = tmp;
    }

    /* ports in one be32 */
    uint32_t ports = ((uint32_t)k->src_port << 16) | (uint32_t)k->dst_port; // BE16|BE16
    w[8] = rte_cpu_to_be_32(ports);

    /* proto in top byte, rest zero */
    w[9] = rte_cpu_to_be_32((uint32_t)k->proto << 24);

    return rte_softrss_be(w, 10, rss_key);
}

/* ---- unified key hash ---- */
static inline uint32_t key_hash(const struct flow_table *ft, const struct flow5 *k)
{
    if (ft->cfg.hash_algo == FT_HASH_CRC32) {
        /* CRC over the fixed-size key is fine for both families */
        return rte_hash_crc(k, sizeof(*k), 0);
    } else if (ft->cfg.hash_algo == FT_HASH_RSS) {
        return (k->family == FT_IPV6)
            ? rss_hash_v6(k, default_rss_key)
            : rss_hash_v4(k, default_rss_key);
    } else {
        return 0;
    }
}
/* ---- internal common table lookup function ---- */
static inline const struct ft_action *lookup_common(const struct flow_table *ft, const struct flow5 *key, uint32_t sig)
{
    //fetch and assign per lcore cache pointer 
    struct l1e *local_l1 = RTE_PER_LCORE(l1);
    uint32_t i = sig & (L1_SIZE-1);

    //check if we have a hot cached copy of the data already, return it if so
    if (likely(local_l1[i].h && memcmp(&local_l1[i].key, key, sizeof(*key)) == 0 )){
        const struct ft_action *a = atomic_load_explicit(&local_l1[i].h->ptr, memory_order_acquire);
        return a ? a : ft->cfg.default_action;
    }

    /* Miss: consult the shard hash (stores handle*) */
    struct indr_action_handle *h = NULL;
    struct rte_hash *hh = ft->s[shard_id(ft, sig)].h;

    if (rte_hash_lookup_with_hash_data(hh, key, sig, (void **)&h) >= 0 && h) {
        /* Refresh L1 (cache the handle, not the action). */
        local_l1[i].key = *key;
        local_l1[i].h   = h;

        const struct ft_action *a = atomic_load_explicit(&h->ptr, memory_order_acquire);
        return a ? a : ft->cfg.default_action;
    }

    return ft->cfg.default_action;
}

/* ---- extenal flow table lookup function, calculates signature hash on call ---- */
const struct ft_action *ft_lookup(const struct flow_table *ft, const struct flow5 *key) {
    return lookup_common(ft, key, key_hash(ft,key));
}

/* ---- extenal flow table lookup function, use precomputed hash (e.g. rss hash provided by NIC) ---- */
const struct ft_action *ft_lookup_prehash(const struct flow_table *ft, const struct flow5 *key, uint32_t sig) {
    return lookup_common(ft, key, sig);
}


/* ---- extenal flow table idle function, readers call this when not accessing / using flow table data ---- */
void ft_reader_idle(struct flow_table *ft, int thread_id){
    rte_rcu_qsbr_quiescent(ft->qs, thread_id);
}


/* ------------------------------ Modification functions (add/modify) --------------------------------------------*/

/* Build a new immutable action on the side (caller’s responsibility). */
static inline struct ft_action *action_dup_init(const struct ft_action *src, int socket)
{
    struct ft_action *a = rte_zmalloc_socket("action", sizeof(*a), RTE_CACHE_LINE_SIZE, socket);
    if (a && src) 
        *a = *src;

    return a;
}

/* Create a indirect handle (one-time for this key) */
static inline struct indr_action_handle *action_handle_create(int socket, struct ft_action *initial)
{
    struct indr_action_handle *h = rte_zmalloc_socket("action_handle", sizeof(*h), RTE_CACHE_LINE_SIZE, socket);
    if (!h) 
        return NULL;
    
    atomic_init(&h->ptr, initial);   /* publish initial with relaxed is fine at init */
    return h;
}

static int entry_valid(struct flow_table *ft, const struct flow5 *k, uint32_t sig){

    // First check if the key exists
    struct indr_action_handle *h;
    int rc = rte_hash_lookup_with_hash_data(ft->s[shard_id(ft,sig)].h, k, sig, (void**)&h);
    if (rc >= 0) {
        // Key already exists → fail
        return -EEXIST;
    }

    return rc;
}

/* ---- extenal flow table add - append function, adds a new entry or flow isn't present, else performs a modify---- */
int ft_append(struct flow_table *ft, const struct flow5 *k, const struct ft_action *init_a){
    int rc = 0;
    //get the hash signature 
    const uint32_t sig = key_hash(ft,k);
    //Check if entry already present 
    rc = entry_valid(ft,k,sig);
    if (rc == -EEXIST){
        rc = ft_replace(ft,k,init_a,NULL);
    }
    else {
        rc = ft_add(ft,k,init_a);
    }

    return rc;
}

/* ---- extenal flow table add function ---- */
int ft_add(struct flow_table *ft, const struct flow5 *k, const struct ft_action *init_a)
{      
    int rc = 0;
    //get the hash signature 
    const uint32_t sig = key_hash(ft,k);

    //Check if entry already present 
    rc = entry_valid(ft,k,sig);
    if (rc == -EEXIST){
        return rc;
    }

    //create a immutable action struct (copies input action fields)
    struct ft_action *new_a = action_dup_init(init_a, ft->cfg.socket_id);
    if (!new_a) {
        return -ENOMEM;
    }

    //create a new indirect action handle 
    struct indr_action_handle *h = action_handle_create(ft->cfg.socket_id, new_a);
    if (!h) { 
        rte_free(new_a); 
        return -ENOMEM; 
    }

    //add indirect action handle with action data to hashtable
    
    rc = rte_hash_add_key_with_hash_data(ft->s[shard_id(ft,sig)].h, k, sig, (void *)h);
    if (rc < 0) {
        /* failure: roll back */
        rte_free(h);
        /* Because no reader could see new_a yet (no handle published), safe to free immediately */
        rte_free(new_a);
    }
    return rc;
}

/* when retiring an action pointer, put it into a qsbr defer queue to be processed later by the ft manager */
static inline void retire_action(struct flow_table *ft, struct ft_action *old)
{
    if (!old) 
        return;
    
    // Start a grace-period token implicitly handled by the dq
    rte_rcu_qsbr_dq_enqueue(ft->dq, &old); // 1 element
    // Do not free here; manager will reclaim later.
}

/* when retiring an indirect action handle pointer, put it into a qsbr defer queue to be processed later by the ft manager */
static inline void retire_indr_handle(struct flow_table *ft, struct indr_action_handle *h)
{
    if (!h) 
        return;

    // Start a grace-period token implicitly handled by the dq
    rte_rcu_qsbr_dq_enqueue(ft->dq, &h); // 1 element
    // Do not free here; manager will reclaim later.
}


/* ---- extenal flow table modify function ---- */
int ft_replace(struct flow_table *ft,const struct flow5 *k,const struct ft_action *new_a_src,struct ft_action **old_a_opt)
{
    //calculate the hash signature of the key
    const uint32_t sig = key_hash(ft,k);
    
    struct indr_action_handle *h = NULL;

    //pick the right hashtable based on shard_id
    struct rte_hash *hh = ft->s[shard_id(ft, sig)].h;

    //Find the handle for this key 
    int lr = rte_hash_lookup_with_hash_data(hh, k, sig, (void **)&h);
    if (lr < 0 || !h) 
        return -ENOENT;

    // Build the new immutable action
    struct ft_action *new_a = action_dup_init(new_a_src, ft->cfg.socket_id);
    if (!new_a) 
        return -ENOMEM;

    /* Publish: single atomic pointer exchange.
       - release on writer makes prior stores to *new_a visible
       - acquire on readers ensures they see a fully built object */
    struct ft_action *old = atomic_exchange_explicit(&h->ptr, new_a, memory_order_release);

    //return old action struct if requested
    if (old_a_opt) 
        *old_a_opt = (struct ft_action *)old;

    //Readers may still hold 'old' in registers/L1 → retire safely
    retire_action(ft, old);
    return 0;
}

/* ---- extenal flow table delete function ---- */
int ft_del(struct flow_table *ft, const struct flow5 *k)
{   
    //calculate the hash signature of the key
    const uint32_t sig = key_hash(ft,k);

    struct indr_action_handle *h = NULL;

    //pick the right hashtable based on shard_id
    struct rte_hash *hh = ft->s[shard_id(ft, sig)].h;

    //Lookup handle first so we can retire after removal
    if (rte_hash_lookup_with_hash_data(hh, k, sig, (void **)&h) < 0 || !h)
        return -ENOENT;

    //if present, delete the entry
    int rc = rte_hash_del_key_with_hash(hh, k, sig);
    if (rc < 0) 
        return rc;

    /* After removal from hash, L1 entries may still hold h.
       If you want to proactively invalidate L1, you can add an epoch/ttl.
       We retire the current action and the handle via RCU callback. */
    struct ft_action *old = atomic_exchange_explicit(&h->ptr, NULL, memory_order_release);
    retire_action(ft, old);
    retire_indr_handle(ft, h);

    return 0;
}