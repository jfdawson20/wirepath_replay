// wpr_tx_encap_rpc.c
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 jfdawson20

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <jansson.h>

#include "wpr_tx_encap_rpc.h"
#include "wpr_ports.h"
#include "wpr_tx_worker.h"

/* ----------------------------- JSON helpers ----------------------------- */

static int
rpc_fail(json_t *reply_root, int rc, const char *msg)
{
    if (reply_root) {
        json_object_set_new(reply_root, "ok", json_false());
        json_object_set_new(reply_root, "rc", json_integer(rc));
        if (msg) json_object_set_new(reply_root, "error", json_string(msg));
    }
    return rc;
}

static void
rpc_ok(json_t *reply_root)
{
    json_object_set_new(reply_root, "ok", json_true());
}

static const char *
jget_str(json_t *o, const char *k)
{
    json_t *v = o ? json_object_get(o, k) : NULL;
    if (!v || !json_is_string(v)) return NULL;
    return json_string_value(v);
}

static bool
jget_bool(json_t *o, const char *k, bool dflt)
{
    json_t *v = o ? json_object_get(o, k) : NULL;
    if (!v) return dflt;
    if (json_is_true(v)) return true;
    if (json_is_false(v)) return false;
    return dflt;
}

static int64_t
jget_i64(json_t *o, const char *k, int64_t dflt)
{
    json_t *v = o ? json_object_get(o, k) : NULL;
    if (!v || !json_is_integer(v)) return dflt;
    return json_integer_value(v);
}

static uint32_t
jget_u32(json_t *o, const char *k, uint32_t dflt)
{
    int64_t x = jget_i64(o, k, (int64_t)dflt);
    if (x < 0) return dflt;
    return (uint32_t)x;
}

static uint16_t
jget_u16(json_t *o, const char *k, uint16_t dflt)
{
    uint32_t x = jget_u32(o, k, dflt);
    return (uint16_t)x;
}

static uint8_t
jget_u8(json_t *o, const char *k, uint8_t dflt)
{
    uint32_t x = jget_u32(o, k, dflt);
    return (uint8_t)x;
}

static json_t *
jget_obj(json_t *o, const char *k)
{
    json_t *v = o ? json_object_get(o, k) : NULL;
    if (!v || !json_is_object(v)) return NULL;
    return v;
}

/* ----------------------------- parse helpers ----------------------------- */

static int
parse_ipv4_host(const char *s, uint32_t *out_host)
{
    if (!s || !out_host) return -EINVAL;
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return -EINVAL;
    *out_host = ntohl(a.s_addr);
    return 0;
}

static int
parse_mac(const char *s, struct rte_ether_addr *out)
{
    if (!s || !out) return -EINVAL;

    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return -EINVAL;
    }
    for (int i = 0; i < 6; i++) out->addr_bytes[i] = (uint8_t)b[i];
    return 0;
}

static wpr_tx_encap_mode_t
parse_mode(const char *s, wpr_tx_encap_mode_t dflt)
{
    if (!s) return dflt;
    if (!strcmp(s, "try_prepend"))   return WPR_ENCAP_TRY_PREPEND;
    if (!strcmp(s, "force_prepend")) return WPR_ENCAP_FORCE_PREPEND;
    if (!strcmp(s, "force_chain"))   return WPR_ENCAP_FORCE_CHAIN;
    return dflt;
}

static wpr_tx_oversize_policy_t
parse_oversize(const char *s, wpr_tx_oversize_policy_t dflt)
{
    if (!s) return dflt;
    if (!strcmp(s, "drop"))      return WPR_OVERSIZE_DROP;
    if (!strcmp(s, "allow"))     return WPR_OVERSIZE_ALLOW;
    if (!strcmp(s, "fragment"))  return WPR_OVERSIZE_FRAGMENT;
    return dflt;
}

static wpr_tx_encap_type_t
parse_type(const char *s)
{
    if (!s) return WPR_ENCAP_NONE;
    if (!strcmp(s, "none"))   return WPR_ENCAP_NONE;
    if (!strcmp(s, "vxlan"))  return WPR_ENCAP_VXLAN;
    if (!strcmp(s, "gre"))    return WPR_ENCAP_GRE;
    if (!strcmp(s, "qinq"))   return WPR_ENCAP_QINQ;
    if (!strcmp(s, "erspan")) return WPR_ENCAP_ERSPAN;
    return WPR_ENCAP_NONE;
}

static wpr_outer_vlan_mode_t
parse_outer_vlan_mode(const char *s)
{
    if (!s) return WPR_OUTER_VLAN_NONE;
    if (!strcmp(s, "none"))  return WPR_OUTER_VLAN_NONE;
    if (!strcmp(s, "8021q")) return WPR_OUTER_VLAN_8021Q;
    if (!strcmp(s, "qinq"))  return WPR_OUTER_VLAN_QINQ;
    return WPR_OUTER_VLAN_NONE;
}

static wpr_vxlan_udp_srcport_mode_t
parse_vxlan_udp_srcport_mode(const char *s)
{
    if (!s) return WPR_VXLAN_UDP_SRCPORT_FIXED;
    if (!strcmp(s, "fixed"))        return WPR_VXLAN_UDP_SRCPORT_FIXED;
    if (!strcmp(s, "hash_inner_l2"))return WPR_VXLAN_UDP_SRCPORT_HASH_INNER_L2;
    if (!strcmp(s, "hash_inner_5tuple")) return WPR_VXLAN_UDP_SRCPORT_HASH_INNER_5TUPLE;
    return WPR_VXLAN_UDP_SRCPORT_FIXED;
}

static wpr_tx_qinq_mode_t
parse_qinq_mode(const char *s)
{
    if (!s) return WPR_QINQ_MODE_PUSH;
    if (!strcmp(s, "push"))            return WPR_QINQ_MODE_PUSH;
    if (!strcmp(s, "replace"))         return WPR_QINQ_MODE_REPLACE;
    if (!strcmp(s, "push_if_untagged"))return WPR_QINQ_MODE_PUSH_IF_UNTAGGED;
    return WPR_QINQ_MODE_PUSH;
}

static wpr_tx_erspan_type_t
parse_erspan_type(const char *s)
{
    if (!s) return WPR_ERSPAN_TYPE_II;
    if (!strcmp(s, "II") || !strcmp(s, "2"))  return WPR_ERSPAN_TYPE_II;
    if (!strcmp(s, "III")|| !strcmp(s, "3"))  return WPR_ERSPAN_TYPE_III;
    return WPR_ERSPAN_TYPE_II;
}

/* Resolve port_index from args.
 * Recommended: args["port_index"].
 * Optional: args["port_id"] -> map by global_port_list if available.
 */
static int
resolve_port_index(const json_t *args, const wpr_thread_args_t *ta, uint16_t *out_port_index, uint16_t *out_port_id)
{
    if (!args || !ta || !out_port_index) return -EINVAL;

    const int64_t port_index_i = jget_i64((json_t *)args, "port_index", -1);
    if (port_index_i >= 0) {
        *out_port_index = (uint16_t)port_index_i;
        if (out_port_id) {
            /* If you can derive dpdk port_id from global_port_list, do it; otherwise leave 0xFFFF. */
            *out_port_id = 0xFFFF;
            if (ta->global_port_list) {
                /* Adjust these field names to your wpr_ports_t definition if needed. */
                /* Most codebases have ports[] where each entry has .port_id */
                extern uint16_t wpr_ports_count(const wpr_ports_t *p); /* optional if you have it */
                (void)wpr_ports_count;
                /* Best-effort: assume global_port_list->ports[] exists and is at least port_index. */
                *out_port_id = ta->global_port_list->ports[*out_port_index].port_id;
            }
        }
        return 0;
    }

    const int64_t port_id_i = jget_i64((json_t *)args, "port_id", -1);
    if (port_id_i >= 0 && ta->global_port_list) {
        uint16_t want = (uint16_t)port_id_i;

        /* Best-effort: assume global_port_list has num_ports + ports[] */
        uint16_t n = 0;
        /* If your struct uses a different name, change this. */
        n = (uint16_t)ta->global_port_list->num_ports;

        for (uint16_t i = 0; i < n; i++) {
            if (ta->global_port_list->ports[i].port_id == want) {
                *out_port_index = i;
                if (out_port_id) *out_port_id = want;
                return 0;
            }
        }
        return -ENOENT;
    }

    return -EINVAL;
}

/* Publish cfg using a seqlock-ish generation counter (odd/even).
 * Requires:
 *   - g->encap_gen is atomic uint64
 *   - g->encap_cfg is plain struct
 */
static void
publish_encap_cfg(wpr_port_stream_global_t *g, const wpr_tx_encap_cfg_t *cfg)
{
    /* make gen odd => writer in progress */
    atomic_fetch_add_explicit(&g->encap_gen, 1, memory_order_acq_rel);

    /* write payload */
    g->encap_cfg = *cfg;

    /* make gen even => publish complete */
    atomic_fetch_add_explicit(&g->encap_gen, 1, memory_order_release);
}

/* Build cfg from JSON args.
 * Schema (recommended):
 * {
 *   "port_index": 0,
 *   "enabled": true,
 *   "type": "vxlan|gre|qinq|erspan|none",
 *   "mode": "try_prepend|force_prepend|force_chain",
 *   "oversize_policy": "drop|allow|fragment",
 *   "outer": {
 *     "src_mac":"..", "dst_mac":"..",
 *     "src_ip":"..", "dst_ip":"..",
 *     "ttl":64, "dscp":0, "df":true,
 *     "outer_vlan": { "enabled":false, "mode":"none|8021q|qinq", ... }
 *   },
 *   "vxlan": { "vni": 1, "udp_dst_port": 4789, "udp_srcport_mode":"fixed|hash_inner_l2|hash_inner_5tuple", "udp_src_port": 5555, "udp_checksum": false },
 *   "gre":   { "teb_mode": true, "key_present": false, "gre_key": 0, "seq_present": false, "seq_start": 0, "csum_present": false },
 *   "qinq":  { "mode":"push|replace|push_if_untagged", "s_vlan_id": 100, "s_pcp":0, "s_dei":0, "c_vlan_id": 200, "c_pcp":0, "c_dei":0, "preserve_existing_vlan": false },
 *   "erspan":{ "type":"II|III", "session_id": 1, "sequence_present": false, "seq_start": 0 }
 * }
 */
static int
parse_cfg_from_args(json_t *args, wpr_tx_encap_cfg_t *cfg, char *err, size_t errlen)
{
    if (!args || !cfg) {
        if (err && errlen) snprintf(err, errlen, "bad args");
        return -EINVAL;
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->enabled = jget_bool(args, "enabled", true);
    cfg->type = parse_type(jget_str(args, "type"));

    cfg->mode = parse_mode(jget_str(args, "mode"), WPR_ENCAP_TRY_PREPEND);
    cfg->oversize_policy = parse_oversize(jget_str(args, "oversize_policy"), WPR_OVERSIZE_DROP);

    cfg->outer_csum_hw_offload = jget_bool(args, "outer_csum_hw_offload", false);

    if (!cfg->enabled || cfg->type == WPR_ENCAP_NONE) {
        cfg->enabled = false;
        cfg->type = WPR_ENCAP_NONE;
        return 0;
    }

    /* Per-type parse */
    json_t *outer = jget_obj(args, "outer");
    if ((cfg->type == WPR_ENCAP_VXLAN) || (cfg->type == WPR_ENCAP_GRE) || (cfg->type == WPR_ENCAP_ERSPAN)) {
        if (!outer) {
            if (err && errlen) snprintf(err, errlen, "missing outer object");
            return -EINVAL;
        }

        const char *smac = jget_str(outer, "src_mac");
        const char *dmac = jget_str(outer, "dst_mac");
        const char *sip  = jget_str(outer, "src_ip");
        const char *dip  = jget_str(outer, "dst_ip");

        if (!smac || !dmac || !sip || !dip) {
            if (err && errlen) snprintf(err, errlen, "outer requires src_mac,dst_mac,src_ip,dst_ip");
            return -EINVAL;
        }
        if (parse_mac(smac, &cfg->outer.outer_src_mac) != 0 ||
            parse_mac(dmac, &cfg->outer.outer_dst_mac) != 0) {
            if (err && errlen) snprintf(err, errlen, "invalid mac format");
            return -EINVAL;
        }
        if (parse_ipv4_host(sip, &cfg->outer.outer_src_ipv4) != 0 ||
            parse_ipv4_host(dip, &cfg->outer.outer_dst_ipv4) != 0) {
            if (err && errlen) snprintf(err, errlen, "invalid ipv4 format");
            return -EINVAL;
        }

        cfg->outer.ttl  = jget_u8(outer, "ttl", 64);
        cfg->outer.dscp = jget_u8(outer, "dscp", 0);
        cfg->outer.df   = jget_bool(outer, "df", true);

        /* Optional outer vlan */
        json_t *ov = jget_obj(outer, "outer_vlan");
        if (ov) {
            cfg->outer.outer_vlan.enabled = jget_bool(ov, "enabled", false);
            cfg->outer.outer_vlan.mode = parse_outer_vlan_mode(jget_str(ov, "mode"));

            if (cfg->outer.outer_vlan.enabled && cfg->outer.outer_vlan.mode == WPR_OUTER_VLAN_8021Q) {
                cfg->outer.outer_vlan.vlan_id = jget_u16(ov, "vlan_id", 0);
                cfg->outer.outer_vlan.pcp     = jget_u8 (ov, "pcp", 0);
                cfg->outer.outer_vlan.dei     = jget_u8 (ov, "dei", 0);
            } else if (cfg->outer.outer_vlan.enabled && cfg->outer.outer_vlan.mode == WPR_OUTER_VLAN_QINQ) {
                cfg->outer.outer_vlan.s_vlan_id = jget_u16(ov, "s_vlan_id", 0);
                cfg->outer.outer_vlan.s_pcp     = jget_u8 (ov, "s_pcp", 0);
                cfg->outer.outer_vlan.s_dei     = jget_u8 (ov, "s_dei", 0);
                cfg->outer.outer_vlan.c_vlan_id = jget_u16(ov, "c_vlan_id", 0);
                cfg->outer.outer_vlan.c_pcp     = jget_u8 (ov, "c_pcp", 0);
                cfg->outer.outer_vlan.c_dei     = jget_u8 (ov, "c_dei", 0);
            }
        }
    }

    switch (cfg->type) {
        case WPR_ENCAP_VXLAN: {
            json_t *vx = jget_obj(args, "vxlan");
            if (!vx) {
                if (err && errlen) snprintf(err, errlen, "missing vxlan object");
                return -EINVAL;
            }
            cfg->u.vxlan.vni = jget_u32(vx, "vni", 0);
            cfg->u.vxlan.udp_dst_port = jget_u16(vx, "udp_dst_port", WPR_VXLAN_UDP_DST_PORT);
            cfg->u.vxlan.udp_srcport_mode = parse_vxlan_udp_srcport_mode(jget_str(vx, "udp_srcport_mode"));
            cfg->u.vxlan.udp_src_port_fixed = jget_u16(vx, "udp_src_port", 5555);
            cfg->u.vxlan.udp_checksum = jget_bool(vx, "udp_checksum", false);
            break;
        }

        case WPR_ENCAP_GRE: {
            json_t *gr = jget_obj(args, "gre");
            if (!gr) {
                if (err && errlen) snprintf(err, errlen, "missing gre object");
                return -EINVAL;
            }
            cfg->u.gre.teb_mode     = jget_bool(gr, "teb_mode", true);
            cfg->u.gre.key_present  = jget_bool(gr, "key_present", false);
            cfg->u.gre.gre_key      = jget_u32(gr, "gre_key", 0);
            cfg->u.gre.seq_present  = jget_bool(gr, "seq_present", false);
            cfg->u.gre.seq_start    = jget_u32(gr, "seq_start", 0);
            cfg->u.gre.csum_present = jget_bool(gr, "csum_present", false);
            break;
        }

        case WPR_ENCAP_QINQ: {
            json_t *qq = jget_obj(args, "qinq");
            if (!qq) {
                if (err && errlen) snprintf(err, errlen, "missing qinq object");
                return -EINVAL;
            }
            cfg->u.qinq.mode = parse_qinq_mode(jget_str(qq, "mode"));
            cfg->u.qinq.s_vlan_id = jget_u16(qq, "s_vlan_id", 0);
            cfg->u.qinq.s_pcp     = jget_u8 (qq, "s_pcp", 0);
            cfg->u.qinq.s_dei     = jget_u8 (qq, "s_dei", 0);
            cfg->u.qinq.c_vlan_id = jget_u16(qq, "c_vlan_id", 0);
            cfg->u.qinq.c_pcp     = jget_u8 (qq, "c_pcp", 0);
            cfg->u.qinq.c_dei     = jget_u8 (qq, "c_dei", 0);
            cfg->u.qinq.preserve_existing_vlan = jget_bool(qq, "preserve_existing_vlan", false);
            break;
        }

        case WPR_ENCAP_ERSPAN: {
            json_t *er = jget_obj(args, "erspan");
            if (!er) {
                if (err && errlen) snprintf(err, errlen, "missing erspan object");
                return -EINVAL;
            }
            cfg->u.erspan.type = parse_erspan_type(jget_str(er, "type"));
            cfg->u.erspan.session_id = jget_u16(er, "session_id", 0);
            cfg->u.erspan.sequence_present = jget_bool(er, "sequence_present", false);
            cfg->u.erspan.seq_start = jget_u32(er, "seq_start", 0);
            break;
        }

        default:
            if (err && errlen) snprintf(err, errlen, "unknown/unsupported type");
            return -EINVAL;
    }

    return 0;
}

/* Convert current config to JSON (best-effort; enough for debugging) */
static json_t *cfg_to_json(const wpr_tx_encap_cfg_t *cfg)
{
    if (!cfg) return json_object();

    json_t *o = json_object();
    json_object_set_new(o, "enabled", cfg->enabled ? json_true() : json_false());

    const char *type =
        (cfg->type == WPR_ENCAP_VXLAN) ? "vxlan" :
        (cfg->type == WPR_ENCAP_GRE)   ? "gre" :
        (cfg->type == WPR_ENCAP_QINQ)  ? "qinq" :
        (cfg->type == WPR_ENCAP_ERSPAN)? "erspan" : "none";
    json_object_set_new(o, "type", json_string(type));

    const char *mode =
        (cfg->mode == WPR_ENCAP_FORCE_PREPEND) ? "force_prepend" :
        (cfg->mode == WPR_ENCAP_FORCE_CHAIN)   ? "force_chain" : "try_prepend";
    json_object_set_new(o, "mode", json_string(mode));

    const char *ov =
        (cfg->oversize_policy == WPR_OVERSIZE_ALLOW) ? "allow" :
        (cfg->oversize_policy == WPR_OVERSIZE_FRAGMENT) ? "fragment" : "drop";
    json_object_set_new(o, "oversize_policy", json_string(ov));

    /* Outer is annoying to stringify without helpers; keep minimal */
    json_t *outer = json_object();
    json_object_set_new(outer, "ttl", json_integer(cfg->outer.ttl));
    json_object_set_new(outer, "dscp", json_integer(cfg->outer.dscp));
    json_object_set_new(outer, "df", cfg->outer.df ? json_true() : json_false());
    json_object_set_new(o, "outer", outer);

    return o;
}

/* ----------------------------- RPC: set ----------------------------- */

int wpr_tx_encap_set(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{
    if (!reply_root || !thread_args) return rpc_fail(reply_root, -EINVAL, "bad args");

    uint16_t port_index = 0xFFFF;
    uint16_t port_id = 0xFFFF;
    int prc = resolve_port_index(args, thread_args, &port_index, &port_id);
    if (prc != 0) return rpc_fail(reply_root, -EINVAL, "missing/invalid port_index or port_id");

    if (!thread_args->port_stream_global_cfg) {
        return rpc_fail(reply_root, -EINVAL, "thread_args->port_stream_global_cfg is NULL");
    }

    wpr_port_stream_global_t *g = &thread_args->port_stream_global_cfg[port_index];

    wpr_tx_encap_cfg_t cfg;
    char perr[256];
    if (parse_cfg_from_args(args, &cfg, perr, sizeof(perr)) != 0) {
        return rpc_fail(reply_root, -EINVAL, perr);
    }

    /* Optional max_inner_l2_len for validation */
    uint32_t max_inner_l2_len = jget_u32(args, "max_inner_l2_len", 0);

    /* Validate against port capabilities (port_id best effort) */
    char verr[256];
    uint16_t validate_port = (port_id != 0xFFFF) ? port_id : (uint16_t)jget_u16(args, "validate_port_id", port_id);
    if (validate_port != 0xFFFF) {
        if (wpr_tx_encap_validate_cfg(validate_port, &cfg, max_inner_l2_len, verr, sizeof(verr)) != 0) {
            return rpc_fail(reply_root, -EINVAL, verr);
        }
    }

    /* Compile for sanity + to report hdr_len/overhead to user */
    wpr_tx_encap_compiled_t compiled;
    char cerr[256];
    if (wpr_tx_encap_compile(&cfg, &compiled, cerr, sizeof(cerr)) != 0) {
        return rpc_fail(reply_root, -EINVAL, cerr);
    }

    /* Publish cfg + bump generation so workers recompile */
    publish_encap_cfg(g, &cfg);

    rpc_ok(reply_root);
    json_object_set_new(reply_root, "port_index", json_integer(port_index));
    if (port_id != 0xFFFF) json_object_set_new(reply_root, "port_id", json_integer(port_id));

    json_object_set_new(reply_root, "encap_type",
                        json_string((cfg.type == WPR_ENCAP_VXLAN) ? "vxlan" :
                                    (cfg.type == WPR_ENCAP_GRE)   ? "gre" :
                                    (cfg.type == WPR_ENCAP_QINQ)  ? "qinq" :
                                    (cfg.type == WPR_ENCAP_ERSPAN)? "erspan" : "none"));

    json_object_set_new(reply_root, "compiled_hdr_len", json_integer(compiled.hdr_len));
    json_object_set_new(reply_root, "wire_overhead_bytes", json_integer(compiled.wire_overhead_bytes));

    /* Return current gen (note: with seqlock publish it will be even after write) */
    uint64_t gen = atomic_load_explicit(&g->encap_gen, memory_order_acquire);
    json_object_set_new(reply_root, "encap_gen", json_integer((json_int_t)gen));

    return 0;
}

/* ----------------------------- RPC: clear ----------------------------- */

int wpr_tx_encap_clear(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{
    if (!reply_root || !thread_args) return rpc_fail(reply_root, -EINVAL, "bad args");

    uint16_t port_index = 0xFFFF;
    uint16_t port_id = 0xFFFF;
    int prc = resolve_port_index(args, thread_args, &port_index, &port_id);
    if (prc != 0) return rpc_fail(reply_root, -EINVAL, "missing/invalid port_index or port_id");

    if (!thread_args->port_stream_global_cfg) {
        return rpc_fail(reply_root, -EINVAL, "thread_args->port_stream_global_cfg is NULL");
    }

    wpr_port_stream_global_t *g = &thread_args->port_stream_global_cfg[port_index];

    wpr_tx_encap_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = false;
    cfg.type = WPR_ENCAP_NONE;
    cfg.mode = WPR_ENCAP_TRY_PREPEND;
    cfg.oversize_policy = WPR_OVERSIZE_DROP;

    publish_encap_cfg(g, &cfg);

    rpc_ok(reply_root);
    json_object_set_new(reply_root, "port_index", json_integer(port_index));
    if (port_id != 0xFFFF) json_object_set_new(reply_root, "port_id", json_integer(port_id));
    json_object_set_new(reply_root, "encap_type", json_string("none"));
    json_object_set_new(reply_root, "encap_gen",
                        json_integer((json_int_t)atomic_load_explicit(&g->encap_gen, memory_order_acquire)));
    return 0;
}

/* ----------------------------- RPC: get ----------------------------- */

int wpr_tx_encap_get(json_t *reply_root, json_t *args, wpr_thread_args_t *thread_args)
{
    if (!reply_root || !thread_args) return rpc_fail(reply_root, -EINVAL, "bad args");

    uint16_t port_index = 0xFFFF;
    uint16_t port_id = 0xFFFF;
    int prc = resolve_port_index(args, thread_args, &port_index, &port_id);
    if (prc != 0) return rpc_fail(reply_root, -EINVAL, "missing/invalid port_index or port_id");

    if (!thread_args->port_stream_global_cfg) {
        return rpc_fail(reply_root, -EINVAL, "thread_args->port_stream_global_cfg is NULL");
    }

    wpr_port_stream_global_t *g = &thread_args->port_stream_global_cfg[port_index];

    /* Seqlock-ish consistent snapshot */
    wpr_tx_encap_cfg_t snap;
    while (1) {
        uint64_t g1 = atomic_load_explicit(&g->encap_gen, memory_order_acquire);
        if (g1 & 1u) continue; /* writer in progress */
        snap = g->encap_cfg;
        uint64_t g2 = atomic_load_explicit(&g->encap_gen, memory_order_acquire);
        if (g1 == g2) break;
    }

    rpc_ok(reply_root);
    json_object_set_new(reply_root, "port_index", json_integer(port_index));
    if (port_id != 0xFFFF) json_object_set_new(reply_root, "port_id", json_integer(port_id));
    json_object_set_new(reply_root, "encap_gen",
                        json_integer((json_int_t)atomic_load_explicit(&g->encap_gen, memory_order_acquire)));
    json_object_set_new(reply_root, "encap_cfg", cfg_to_json(&snap));
    return 0;
}
