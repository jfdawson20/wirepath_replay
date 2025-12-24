#ifndef WPR_HELPERS_H
#define WPR_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_byteorder.h>

/**
* Parse a MAC address string into rte_ether_addr structure.
* Example: "01:23:45:67:89:ab"
* @param s
*   MAC address string.
* @param mac
*   Pointer to output rte_ether_addr structure.
* @return
*   0 on success, negative errno on failure.
**/
static inline int parse_mac(const char *s, struct rte_ether_addr *mac)
{
    unsigned int b[6];
    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -EINVAL;

    for (int i = 0; i < 6; i++)
        mac->addr_bytes[i] = (uint8_t)b[i];
    return 0;
}

#endif /* WPR_HELPERS_H */