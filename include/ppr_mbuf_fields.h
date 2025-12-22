#ifndef MBUF_FIELDS_H
#define MBUF_FIELDS_H
#include <rte_mbuf_dyn.h>
#include <rte_mbuf.h>

#include "ppr_actions.h"


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

typedef struct ppr_priv{
    //epoch version since last policy action update
    ppr_global_policy_epoch_t epoch; 
    
    //pending action to apply to this packet
    ppr_policy_action_t pending_policy_action;
} ppr_priv_t __rte_cache_aligned;


/* ---------------------------- Mbuf Private Area Accessor Functions ------------------ */
/** 
* Get pointer to ppr_priv_t structure in mbuf private area
* @param m
*   Packet mbuf
* @return
*   Pointer to ppr_priv_t structure 
**/
static inline ppr_priv_t *ppr_priv(struct rte_mbuf *m) {
    return (ppr_priv_t *)rte_mbuf_to_priv(m);
}


/** 
* Reset ppr_priv_t structure to default values
* @param priv
*   Pointer to ppr_priv_t structure
**/
static inline void ppr_priv_reset(ppr_priv_t *priv)
{
    __builtin_memset(priv, 0, sizeof(*priv));
}

/** 
* Copy an mbuf along with its ppr_priv_t structure
* @param m
*   Packet mbuf to clone
* @param pool
*   Mempool to allocate clone from
* @return
*   Pointer to cloned mbuf with copied ppr_priv_t structure, or NULL on failure 
**/
static inline struct rte_mbuf *ppr_copy_with_priv(struct rte_mbuf *m, struct rte_mempool *pool)
{
    struct rte_mbuf *c = rte_pktmbuf_copy(m, pool,0,UINT32_MAX);
    if (c == NULL)
        return NULL;

    ppr_priv_t *src = ppr_priv(m);
    ppr_priv_t *dst = ppr_priv(c);

    *dst = *src;   // or memcpy(dst, src, sizeof(*dst));

    return c;
}


#endif