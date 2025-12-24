// mbuf_fields.c
#include <stdlib.h>
#include <errno.h>
#include <rte_errno.h>
#include <rte_mbuf_dyn.h>
#include <rte_log.h> 
#include <rte_common.h>
#include "wpr_mbuf_fields.h"

void init_mbuf_tstamps(int *offset) {
    const struct rte_mbuf_dynfield my_desc = {
        .name  = "myapp_dynfield_ts",
        .size  = sizeof(uint64_t),
        .align = __alignof__(uint64_t),
        .flags = 0,
    };
    *offset = rte_mbuf_dynfield_register(&my_desc);
    if (*offset == -1) {
        if (rte_errno == EEXIST)
            *offset = rte_mbuf_dynfield_lookup(my_desc.name, NULL);
        if (*offset == -1)
            rte_exit(EXIT_FAILURE, "dynfield reg/lookup failed: %s\n", rte_strerror(rte_errno));
    }
}
