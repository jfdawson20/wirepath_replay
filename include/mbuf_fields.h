#ifndef MBUF_FIELDS_H
#define MBUF_FIELDS_H
#include <rte_mbuf_dyn.h>
#include <rte_mbuf.h>

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
#endif