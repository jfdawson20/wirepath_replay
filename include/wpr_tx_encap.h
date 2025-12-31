#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define WPR_TX_ENCAP_MAX_HDR     128
#define WPR_VXLAN_UDP_DST_PORT   4789

typedef enum {
    WPR_ENCAP_NONE = 0,
    WPR_ENCAP_VXLAN,
    WPR_ENCAP_GRE,
    WPR_ENCAP_QINQ,
    WPR_ENCAP_ERSPAN,
} wpr_tx_encap_type_t;

typedef enum {
    WPR_OVERSIZE_DROP = 0,
    WPR_OVERSIZE_ALLOW,      /* send anyway (may get dropped by NIC) */
    WPR_OVERSIZE_FRAGMENT,   /* only meaningful for outer IPv4 (future) */
} wpr_tx_oversize_policy_t;

typedef enum {
    WPR_ENCAP_TRY_PREPEND = 0, /* prefer in-place prepend, fallback to chain if allowed */
    WPR_ENCAP_FORCE_PREPEND,
    WPR_ENCAP_FORCE_CHAIN,
} wpr_tx_encap_mode_t;

typedef enum {
    WPR_VXLAN_UDP_SRCPORT_FIXED = 0,
    WPR_VXLAN_UDP_SRCPORT_HASH_INNER_5TUPLE, /* optional for inner parsing */
    WPR_VXLAN_UDP_SRCPORT_HASH_INNER_L2,     /* cheaper */
} wpr_vxlan_udp_srcport_mode_t;

/* Underlay outer VLAN tags (on the *outer* Ethernet header). Optional. */
typedef enum {
    WPR_OUTER_VLAN_NONE = 0,
    WPR_OUTER_VLAN_8021Q,
    WPR_OUTER_VLAN_QINQ,
} wpr_outer_vlan_mode_t;

typedef struct {
    bool enabled;
    wpr_outer_vlan_mode_t mode;

    /* 802.1Q */
    uint16_t vlan_id;   /* 0..4095 */
    uint8_t  pcp;       /* 0..7 */
    uint8_t  dei;       /* 0..1 */

    /* QinQ (outer S-tag + inner C-tag) */
    uint16_t s_vlan_id; uint8_t s_pcp; uint8_t s_dei;
    uint16_t c_vlan_id; uint8_t c_pcp; uint8_t c_dei;
} wpr_outer_vlan_cfg_t;

typedef struct {
    /* Always applied for VXLAN/GRE/ERSPAN. Not used for QinQ-only. */
    struct rte_ether_addr outer_src_mac;
    struct rte_ether_addr outer_dst_mac;

    uint32_t outer_src_ipv4; /* host-order */
    uint32_t outer_dst_ipv4; /* host-order */

    uint8_t  ttl;            /* default 64 */
    uint8_t  dscp;           /* 0..63, optional */
    bool     df;             /* IPv4 DF bit */

    wpr_outer_vlan_cfg_t outer_vlan;
} wpr_tx_outer_common_t;


/* Per encap config type and union structure */

//vxlan
typedef struct {
    uint32_t vni;                  /* 24-bit */
    uint16_t udp_dst_port;         /* default 4789 */
    wpr_vxlan_udp_srcport_mode_t udp_srcport_mode;
    uint16_t udp_src_port_fixed;   /* used when mode=fixed */
    bool     udp_checksum;         /* default false (0 is common on IPv4 VXLAN) */
} wpr_tx_vxlan_cfg_t;

//gre
typedef struct {
    bool     teb_mode;             /* true => Ethernet-over-GRE (recommended) */
    bool     key_present;
    uint32_t gre_key;              /* host-order */
    bool     seq_present;
    uint32_t seq_start;            /* host-order */
    bool     csum_present;         /* usually false */
} wpr_tx_gre_cfg_t;

//qinq
typedef enum {
    WPR_QINQ_MODE_PUSH = 0,
    WPR_QINQ_MODE_REPLACE,         /* if pkt already VLAN-tagged, replace with QinQ */
    WPR_QINQ_MODE_PUSH_IF_UNTAGGED,
} wpr_tx_qinq_mode_t;

typedef struct {
    wpr_tx_qinq_mode_t mode;
    uint16_t s_vlan_id; uint8_t s_pcp; uint8_t s_dei;
    uint16_t c_vlan_id; uint8_t c_pcp; uint8_t c_dei;
    bool preserve_existing_vlan;   /* if existing VLAN present, keep it (push deeper) */
} wpr_tx_qinq_cfg_t;


//ERSPAN
typedef enum {
    WPR_ERSPAN_TYPE_II = 2,
    WPR_ERSPAN_TYPE_III = 3,
} wpr_tx_erspan_type_t;

typedef struct {
    wpr_tx_erspan_type_t type;
    uint16_t session_id;     /* or span_id depending on your chosen layout */
    bool sequence_present;
    uint32_t seq_start;

    /* NOTE: ERSPAN bitfield layout is fiddly; isolate it in a builder. */
} wpr_tx_erspan_cfg_t;


// Full encapsulation configuration
typedef struct {
    bool enabled;
    wpr_tx_encap_type_t type;

    wpr_tx_encap_mode_t mode;
    wpr_tx_oversize_policy_t oversize_policy;

    bool outer_csum_hw_offload; /* optional: start with software checksums */

    wpr_tx_outer_common_t outer;

    union {
        wpr_tx_vxlan_cfg_t  vxlan;
        wpr_tx_gre_cfg_t    gre;
        wpr_tx_qinq_cfg_t   qinq;
        wpr_tx_erspan_cfg_t erspan;
    } u;
} wpr_tx_encap_cfg_t;


/* Compiled/prepared encapsulation for fast application - this is what tx_worker references*/
typedef struct {
    bool enabled;
    wpr_tx_encap_type_t type;
    wpr_tx_encap_mode_t mode;
    wpr_tx_oversize_policy_t oversize_policy;

    /* For prepend-type encapsulations: a ready-to-copy header blob. */
    uint16_t hdr_len;
    uint16_t outer_l2_len; /* bytes */
    uint16_t outer_l3_len; /* bytes (IPv4=20) */
    uint16_t outer_l4_len; /* bytes (UDP/GRE/ERSPAN “l4-ish”) */

    /* Offsets into hdr_bytes for patching lengths/checksums quickly */
    uint16_t ofs_ipv4;      /* start of rte_ipv4_hdr */
    uint16_t ofs_udp;       /* start of rte_udp_hdr (vxlan only) */
    uint16_t ofs_gre;       /* start of gre header (gre/erspan) */
    uint16_t ofs_vxlan;     /* start of vxlan header (vxlan) */

    /* Prebuilt header bytes (outer eth + optional VLAN tags + outer ip + ...) */
    uint8_t  hdr_bytes[WPR_TX_ENCAP_MAX_HDR];

    /* QinQ path: not just a blob prepend; needs L2 surgery */
    wpr_tx_qinq_cfg_t qinq;

    /* Derived overhead for validation */
    uint16_t wire_overhead_bytes; /* what we add to inner frame */
} wpr_tx_encap_compiled_t;


/* ----------------------- Encap API Declarations ----------------------------------*/

/* Validate user cfg vs. port capabilities + expected max inner frame size */
int wpr_tx_encap_validate_cfg(uint16_t port_id,
                              const wpr_tx_encap_cfg_t *cfg,
                              uint32_t max_inner_l2_len,
                              char *err, size_t errlen);

/* Compile cfg into a per-worker compiled object (build header bytes, offsets, overhead) */
int wpr_tx_encap_compile(const wpr_tx_encap_cfg_t *cfg,
                         wpr_tx_encap_compiled_t *out,
                         char *err, size_t errlen);

/* Apply compiled encapsulation to a packet.
 * Returns (possibly new) mbuf pointer or NULL (drop).
 * If it allocates a new header mbuf (chaining), it will free the original on failure.
 */
struct rte_mbuf *wpr_tx_encap_apply(struct rte_mbuf *m,
                                   const wpr_tx_encap_compiled_t *c,
                                   struct rte_mempool *tx_pool,
                                   uint16_t port_id);

                                   