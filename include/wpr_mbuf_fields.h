#ifndef MBUF_FIELDS_H
#define MBUF_FIELDS_H
#include <rte_mbuf_dyn.h>
#include <rte_mbuf.h>

#include "wpr_actions.h"
#include "wpr_header_extract.h"


void init_mbuf_tstamps(int *offset);  // declaration only

static inline uint64_t *my_ts_ptr(struct rte_mbuf *m, int off) {
    return RTE_MBUF_DYNFIELD(m, off, uint64_t *);
}
static inline void my_ts_set(struct rte_mbuf *m, int off, uint64_t v) {
    *RTE_MBUF_DYNFIELD(m, off, uint64_t *) = v;
}
static inline uint64_t my_ts_get(const struct rte_mbuf *m, int off) {
    const uint64_t *p = RTE_MBUF_DYNFIELD((struct rte_mbuf *)m, off, const uint64_t *);
    return *p;
}

/* ----------------------- Per MBUF Private area ------------------------- */

typedef struct wpr_priv{
    //epoch version since last policy action update
    wpr_global_policy_epoch_t epoch; 
    
    //pending action to apply to this packet
    wpr_policy_action_t pending_policy_action;
    uint32_t acl_policy_index;
    wpr_l3_t acl_policy_type;
} wpr_priv_t __rte_cache_aligned;


/* ---------------------------- Mbuf Private Area Accessor Functions ------------------ */
/** 
* Get pointer to wpr_priv_t structure in mbuf private area
* @param m
*   Packet mbuf
* @return
*   Pointer to wpr_priv_t structure 
**/
static inline wpr_priv_t *wpr_priv(struct rte_mbuf *m) {
    return (wpr_priv_t *)rte_mbuf_to_priv(m);
}


/** 
* Reset wpr_priv_t structure to default values
* @param priv
*   Pointer to wpr_priv_t structure
**/
static inline void wpr_priv_reset(wpr_priv_t *priv)
{
    __builtin_memset(priv, 0, sizeof(*priv));
}

/** 
* Copy an mbuf along with its wpr_priv_t structure
* @param m
*   Packet mbuf to clone
* @param pool
*   Mempool to allocate clone from
* @return
*   Pointer to cloned mbuf with copied wpr_priv_t structure, or NULL on failure 
**/
static inline struct rte_mbuf *wpr_copy_with_priv(struct rte_mbuf *m, struct rte_mempool *pool)
{
    struct rte_mbuf *c = rte_pktmbuf_copy(m, pool,0,UINT32_MAX);
    if (c == NULL)
        return NULL;

    wpr_priv_t *src = wpr_priv(m);
    wpr_priv_t *dst = wpr_priv(c);

    *dst = *src;   // or memcpy(dst, src, sizeof(*dst));

    return c;
}


#endif