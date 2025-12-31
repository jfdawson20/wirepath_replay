#!/usr/bin/env python3
"""
wpr_traffic_ctl.py - Friendly Python wrapper for WPR Traffic / PCAP replay JSON-RPC API.

This mirrors the style of your wpr_acl.py and uses WpsControlClient from wpr_cli.py.

Commands implemented (from your C RPC table):
  - wpr_get_loaded_pcaps_list
  - wpr_load_pcap_file
  - wpr_assign_port_slot
  - wpr_cmd_get_port_list
  - wpr_port_tx_ctl
  - wpr_set_port_stream_vcs
  - wpr_set_target_rate

New (tx encap):
  - wpr_tx_encap_set
  - wpr_tx_encap_clear
  - wpr_tx_encap_get
"""

from __future__ import annotations

import argparse
import re
from typing import Any, Dict, List, Optional

from prettytable import PrettyTable

from wpr_cli import WpsControlClient, WpsControlError  # adjust path if needed


# ---------------------------------------------------------------------------
# Wire command names
# ---------------------------------------------------------------------------

CMD_GET_LOADED_PCAPS_LIST = "wpr_get_loaded_pcaps_list"
CMD_LOAD_PCAP_FILE = "wpr_load_pcap_file"
CMD_ASSIGN_PORT_SLOT = "wpr_assign_port_slot"

CMD_GET_PORT_LIST = "wpr_cmd_get_port_list"
CMD_PORT_TX_CTL = "wpr_port_tx_ctl"

CMD_SET_PORT_STREAM_VCS = "wpr_set_port_stream_vcs"
CMD_SET_TARGET_RATE = "wpr_set_target_rate"

CMD_TX_ENCAP_SET = "wpr_tx_encap_set"
CMD_TX_ENCAP_CLEAR = "wpr_tx_encap_clear"
CMD_TX_ENCAP_GET = "wpr_tx_encap_get"


# ---------------------------------------------------------------------------
# Optional enums / helpers
# ---------------------------------------------------------------------------

PACE_MODE_NAME_TO_ID: Dict[str, int] = {
    # Placeholders; update to match your C enum values if you want name support.
    "disabled": 0,
    "asap": 0,
    "realtime": 1,
    "pps": 2,
}

START_MODE_NAME_TO_ID: Dict[str, int] = {
    # Placeholders; update to match your C enum values if you want name support.
    "immediate": 0,
    "armed": 1,
    "manual": 2,
}


def _resolve_pace_mode(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        pass
    key = value.strip().lower()
    if key not in PACE_MODE_NAME_TO_ID:
        raise ValueError(
            f"Unknown pace_mode '{value}'. Use an int or one of: {', '.join(sorted(PACE_MODE_NAME_TO_ID))}"
        )
    return int(PACE_MODE_NAME_TO_ID[key])


def _resolve_start_mode(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        pass
    key = value.strip().lower()
    if key not in START_MODE_NAME_TO_ID:
        raise ValueError(
            f"Unknown start_mode '{value}'. Use an int or one of: {', '.join(sorted(START_MODE_NAME_TO_ID))}"
        )
    return int(START_MODE_NAME_TO_ID[key])


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


_PORT_RE = re.compile(r"^port(\d+)$", re.IGNORECASE)


def _port_index_from_name(portname: str) -> Optional[int]:
    """
    Best-effort: 'port0' -> 0
    Returns None if it doesn't match.
    """
    if not portname:
        return None
    m = _PORT_RE.match(portname.strip())
    if not m:
        return None
    return int(m.group(1))


def _pick_port_index(port_index: Optional[int], portname: Optional[str]) -> int:
    if port_index is not None:
        return int(port_index)
    if portname:
        pi = _port_index_from_name(portname)
        if pi is not None:
            return pi
    raise ValueError("Must provide --port-index or a --portname like 'port0'.")


def _fmt_bytes(n: Any) -> Any:
    try:
        n = int(n)
    except Exception:
        return n
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def _fmt_ns(ns: Any) -> Any:
    try:
        ns = int(ns)
    except Exception:
        return ns
    return f"{ns / 1e9:.6f}s"


# ---------------------------------------------------------------------------
# High-level client wrapper
# ---------------------------------------------------------------------------

class WprTrafficClient:
    """
    High-level wrapper around Traffic / PCAP replay JSON-RPC commands.
    """

    def __init__(self, ctl: WpsControlClient) -> None:
        self.ctl = ctl

    def get_loaded_pcaps_list(self) -> Dict[str, Any]:
        return self.ctl.call(CMD_GET_LOADED_PCAPS_LIST)

    def load_pcap_file(self, filename: str) -> Dict[str, Any]:
        return self.ctl.call(CMD_LOAD_PCAP_FILE, args={"filename": filename})

    def assign_port_slot(
        self,
        port: str,
        slotid: int,
        pace_mode: int,
        start_mode: int,
        fixed_index: int,
        replay_window_sec: float,
    ) -> Dict[str, Any]:
        payload = {
            "port": port,
            "slotid": int(slotid),
            "pace_mode": int(pace_mode),
            "start_mode": int(start_mode),
            "fixed_index": int(fixed_index),
            "replay_window_sec": float(replay_window_sec),
        }
        return self.ctl.call(CMD_ASSIGN_PORT_SLOT, args=payload)

    def get_port_list(self) -> Dict[str, Any]:
        return self.ctl.call(CMD_GET_PORT_LIST)

    def port_tx_ctl(self, port: str, cmd: str) -> Dict[str, Any]:
        cmd_l = cmd.strip().lower()
        if cmd_l not in ("enable", "disable"):
            raise ValueError("cmd must be 'enable' or 'disable'")
        return self.ctl.call(CMD_PORT_TX_CTL, args={"port": port, "cmd": cmd_l})

    def set_port_stream_vcs(self, port: str, num_vcs: int) -> Dict[str, Any]:
        payload = {
            "port": port,
            "num_vcs": int(num_vcs),
        }
        return self.ctl.call(CMD_SET_PORT_STREAM_VCS, args=payload)

    def set_target_rate(self, port: str, target_kind: str, target_value: float) -> Dict[str, Any]:
        kind = (target_kind or "").strip().lower()
        if kind not in ("bps", "pps"):  # extend later if you add cps
            raise ValueError("target_kind must be 'bps' or 'pps'")
        payload = {
            "port": port,
            "target_kind": kind,
            "target_value": float(target_value),
        }
        return self.ctl.call(CMD_SET_TARGET_RATE, args=payload)

    # ---------------- tx encap ----------------

    def tx_encap_set(self, port_index: int, encap_args: Dict[str, Any]) -> Dict[str, Any]:
        payload = {"port_index": int(port_index)}
        payload.update(encap_args)
        return self.ctl.call(CMD_TX_ENCAP_SET, args=payload)

    def tx_encap_clear(self, port_index: int) -> Dict[str, Any]:
        return self.ctl.call(CMD_TX_ENCAP_CLEAR, args={"port_index": int(port_index)})

    def tx_encap_get(self, port_index: int) -> Dict[str, Any]:
        return self.ctl.call(CMD_TX_ENCAP_GET, args={"port_index": int(port_index)})


# ---------------------------------------------------------------------------
# Pretty display helpers (tolerant to schema variations)
# ---------------------------------------------------------------------------

def display_ports(reply: Dict[str, Any]) -> None:
    port_list = reply.get("port_list", {})

    t = PrettyTable()
    t.field_names = ["Port", "Port ID", "External", "Dir", "RXQs", "TXQs", "RXQ->Core", "TXQ->Core"]

    if not isinstance(port_list, dict) or not port_list:
        print("Ports: (none)")
        if "status" in reply:
            print(f"status: {reply.get('status')}")
        print("")
        return

    def _sort_key(k: str):
        if k.startswith("port") and k[4:].isdigit():
            return (0, int(k[4:]))
        return (1, k)

    for port_name in sorted(port_list.keys(), key=_sort_key):
        p = port_list.get(port_name, {})
        if not isinstance(p, dict):
            t.add_row([port_name, "", "", "", "", "", "", ""])
            continue

        name = p.get("name", port_name)
        port_id = p.get("port_id", "")
        is_external = p.get("is_external", "")
        direction = p.get("dir", "")

        total_rx = p.get("total_rx_queues", "")
        total_tx = p.get("total_tx_queues", "")

        rxq_map = []
        for q in p.get("rx_queues", []) or []:
            if not isinstance(q, dict):
                continue
            qi = q.get("queue_index", "")
            core = q.get("assigned_worker_core", "")
            rxq_map.append(f"{qi}:{core}")

        txq_map = []
        for q in p.get("tx_queues", []) or []:
            if not isinstance(q, dict):
                continue
            qi = q.get("queue_index", "")
            core = q.get("assigned_worker_core", "")
            txq_map.append(f"{qi}:{core}")

        t.add_row([name, port_id, is_external, direction, total_rx, total_tx, ",".join(rxq_map), ",".join(txq_map)])

    print("Ports:")
    print(t)
    if "status" in reply:
        print(f"\nstatus: {reply.get('status')}")
    print("")


def display_loaded_pcaps(reply: Dict[str, Any]) -> None:
    def _fmt_rate(v, unit):
        if v in ("", None):
            return ""
        try:
            return f"{float(v):,.2f} {unit}"
        except Exception:
            return str(v)

    def _fmt_int(v):
        if v in ("", None):
            return ""
        try:
            return f"{int(v):,}"
        except Exception:
            return str(v)

    slots = (
        reply.get("loaded_pcaps")
        or reply.get("slots")
        or reply.get("pcaps")
        or reply.get("loaded")
        or reply.get("results")
        or []
    )
    slots = _as_list(slots)

    t = PrettyTable()
    t.field_names = [
        "Slot", "PCAP", "Pkts", "Size", "Δ Time",
        "Native PPS", "Native BPS", "Native CPS", "Native Unique Conns",
        "Mode", "Last Tune", "Tune Target", "Chosen VC", "Predicted",
    ]

    for s in slots:
        if not isinstance(s, dict):
            t.add_row(["", str(s)] + [""] * (len(t.field_names) - 2))
            continue

        slotid   = s.get("slotid", s.get("slot_id", s.get("id", "")))
        name     = s.get("pcap_name", s.get("filename", s.get("file", "")))
        packets  = s.get("pcap_packets", s.get("packets", ""))
        size_b   = s.get("size_in_bytes", s.get("bytes", ""))
        delta_ns = s.get("delta_ns", "")
        mode     = s.get("mode", "")

        native_pps = s.get("native_pps", "")
        native_bps = s.get("native_bps", "")
        native_cps = s.get("native_cps", "")
        native_unique_conns = s.get("native_unique_conns", "")

        tune_kind   = s.get("last_autotune_kind", "")
        tune_target = s.get("last_autotune_target", "")
        tune_vc     = s.get("last_autotune_chosen_vc", "")
        tune_pred   = s.get("last_autotune_predicted_total", "")

        t.add_row([
            slotid,
            name,
            _fmt_int(packets),
            _fmt_bytes(size_b),
            _fmt_ns(delta_ns),
            _fmt_rate(native_pps, "pps"),
            _fmt_rate(native_bps, "bps"),
            _fmt_rate(native_cps, "cps"),
            _fmt_int(native_unique_conns),
            mode,
            tune_kind,
            _fmt_rate(tune_target, ""),
            tune_vc,
            _fmt_rate(tune_pred, ""),
        ])

    print("Loaded PCAPs:")
    print(t)
    print("")


def display_generic_reply(title: str, reply: Dict[str, Any]) -> None:
    t = PrettyTable()
    t.field_names = ["Key", "Value"]
    for k in sorted(reply.keys()):
        t.add_row([k, reply[k]])
    print(f"{title}:")
    print(t)
    print("")


def display_encap_reply(title: str, reply: Dict[str, Any]) -> None:
    """
    Pretty print common keys returned by your encap RPCs:
      ok, rc, error, port_index, port_id, encap_type, compiled_hdr_len, wire_overhead_bytes, encap_gen, encap_cfg
    """
    t = PrettyTable()
    t.field_names = ["Key", "Value"]
    prefer = [
        "ok", "rc", "error",
        "port_index", "port_id",
        "encap_type", "compiled_hdr_len", "wire_overhead_bytes",
        "encap_gen",
        "encap_cfg",
    ]
    used = set()
    for k in prefer:
        if k in reply:
            t.add_row([k, reply[k]])
            used.add(k)
    for k in sorted(reply.keys()):
        if k not in used:
            t.add_row([k, reply[k]])
    print(f"{title}:")
    print(t)
    print("")


# ---------------------------------------------------------------------------
# Encap payload builder (CLI -> JSON dict for RPC)
# ---------------------------------------------------------------------------

def build_encap_payload_from_cli(a: argparse.Namespace) -> Dict[str, Any]:
    """
    Build the args dict expected by wpr_tx_encap_set.
    """
    encap_type = (a.type or "none").strip().lower()

    payload: Dict[str, Any] = {
        "enabled": (not a.disable) and (encap_type != "none"),
        "type": encap_type,
        "mode": a.mode,
        "oversize_policy": a.oversize_policy,
        "outer_csum_hw_offload": bool(a.outer_csum_hw_offload),
    }

    if a.max_inner_l2_len is not None:
        payload["max_inner_l2_len"] = int(a.max_inner_l2_len)

    # QinQ (L2 surgery) does not require an "outer" block
    needs_outer = encap_type in ("vxlan", "gre", "erspan")
    if needs_outer:
        if not (a.outer_src_mac and a.outer_dst_mac and a.outer_src_ip and a.outer_dst_ip):
            raise ValueError("For vxlan/gre/erspan you must set --outer-src-mac/--outer-dst-mac/--outer-src-ip/--outer-dst-ip")

        outer: Dict[str, Any] = {
            "src_mac": a.outer_src_mac,
            "dst_mac": a.outer_dst_mac,
            "src_ip": a.outer_src_ip,
            "dst_ip": a.outer_dst_ip,
            "ttl": int(a.outer_ttl),
            "dscp": int(a.outer_dscp),
            "df": bool(a.outer_df),
        }

        # Optional outer VLAN for underlay
        if a.outer_vlan_mode and a.outer_vlan_mode != "none":
            ov: Dict[str, Any] = {
                "enabled": True,
                "mode": a.outer_vlan_mode,
            }
            if a.outer_vlan_mode == "8021q":
                if a.outer_vlan_id is None:
                    raise ValueError("--outer-vlan-id is required when --outer-vlan-mode=8021q")
                ov.update({
                    "vlan_id": int(a.outer_vlan_id),
                    "pcp": int(a.outer_vlan_pcp),
                    "dei": int(a.outer_vlan_dei),
                })
            elif a.outer_vlan_mode == "qinq":
                if a.outer_s_vlan_id is None or a.outer_c_vlan_id is None:
                    raise ValueError("--outer-s-vlan-id and --outer-c-vlan-id are required when --outer-vlan-mode=qinq")
                ov.update({
                    "s_vlan_id": int(a.outer_s_vlan_id),
                    "s_pcp": int(a.outer_s_vlan_pcp),
                    "s_dei": int(a.outer_s_vlan_dei),
                    "c_vlan_id": int(a.outer_c_vlan_id),
                    "c_pcp": int(a.outer_c_vlan_pcp),
                    "c_dei": int(a.outer_c_vlan_dei),
                })
            outer["outer_vlan"] = ov

        payload["outer"] = outer

    # Per-type blocks
    if encap_type == "vxlan":
        if a.vni is None:
            raise ValueError("--vni is required for vxlan")
        payload["vxlan"] = {
            "vni": int(a.vni),
            "udp_dst_port": int(a.udp_dst_port),
            "udp_srcport_mode": a.udp_srcport_mode,
            "udp_src_port": int(a.udp_src_port),
            "udp_checksum": bool(a.udp_checksum),
        }

    elif encap_type == "gre":
        gre: Dict[str, Any] = {
            "teb_mode": bool(a.gre_teb_mode),
            "key_present": a.gre_key is not None,
            "gre_key": int(a.gre_key or 0),
            "seq_present": a.gre_seq_start is not None,
            "seq_start": int(a.gre_seq_start or 0),
            "csum_present": bool(a.gre_csum),
        }
        payload["gre"] = gre

    elif encap_type == "qinq":
        if a.s_vlan_id is None or a.c_vlan_id is None:
            raise ValueError("--s-vlan-id and --c-vlan-id are required for qinq")
        payload["qinq"] = {
            "mode": a.qinq_mode,
            "s_vlan_id": int(a.s_vlan_id),
            "s_pcp": int(a.s_pcp),
            "s_dei": int(a.s_dei),
            "c_vlan_id": int(a.c_vlan_id),
            "c_pcp": int(a.c_pcp),
            "c_dei": int(a.c_dei),
            "preserve_existing_vlan": bool(a.preserve_existing_vlan),
        }

    elif encap_type == "erspan":
        if a.session_id is None:
            raise ValueError("--session-id is required for erspan")
        payload["erspan"] = {
            "type": a.erspan_type,
            "session_id": int(a.session_id),
            "sequence_present": a.erspan_seq_start is not None,
            "seq_start": int(a.erspan_seq_start or 0),
        }

    elif encap_type == "none":
        # allow explicit disable
        payload["enabled"] = False

    else:
        raise ValueError(f"Unknown encap type: {encap_type}")

    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WPR Traffic / PCAP replay control client")

    p.add_argument("-p", "--port", type=int, default=9000, help="RPC Server Port")
    p.add_argument("-i", "--hostip", type=str, default="localhost", help="RPC Server Address")

    sp = p.add_subparsers(dest="command", required=True)

    # ---- ports ----
    sp.add_parser("ports", help="List all ports configured in the application")

    p_tx = sp.add_parser("tx", help="Enable or disable transmission on a port")
    p_tx.add_argument("portname", help="Port name")
    p_tx.add_argument("cmd", choices=["enable", "disable"], help="TX control")

    # ---- pcaps ----
    sp.add_parser("pcaps", help="List loaded pcap files in memory")

    p_load = sp.add_parser("load", help="Load a pcap file into memory")
    p_load.add_argument("filename", help="Path to pcap file")

    # ---- assign ----
    p_asg = sp.add_parser("assign", help="Assign a loaded pcap slot to a port for replay")
    p_asg.add_argument("--portname", required=True, help="Port name")
    p_asg.add_argument("--slotid", required=True, type=int, help="Loaded pcap slot id")
    p_asg.add_argument("--pace-mode", default="0", help="pace_mode (int or name). Examples: 0, 1, realtime, pps")
    p_asg.add_argument("--start-mode", default="0", help="start_mode (int or name). Examples: 0, 1, immediate, armed")
    p_asg.add_argument("--fixed-index", type=int, default=0, help="fixed_index (int).")
    p_asg.add_argument("--replay-window-sec", type=float, default=0, help="replay_window_sec (float).")

    # ---- vcs ----
    p_vcs = sp.add_parser("vcs", help="Set number of active virtual clients (VCs) for a port stream")
    p_vcs.add_argument("--portname", required=True, help="Port name")
    p_vcs.add_argument("--num-vcs", required=True, type=int, help="Number of active VCs (clients)")

    # ---- target rate ----
    p_rate = sp.add_parser("rate", help="Set target rate for a port stream (bps or pps)")
    p_rate.add_argument("--portname", required=True, help="Port name")
    p_rate.add_argument("--kind", required=True, choices=["bps", "pps"], help="Target kind")
    p_rate.add_argument("--value", required=True, type=float, help="Target value (float)")

    # ---- encap get/clear/set ----
    p_enc_get = sp.add_parser("encap-get", help="Get tx encapsulation config for a port stream")
    p_enc_get.add_argument("--port-index", type=int, default=None, help="Port index (preferred)")
    p_enc_get.add_argument("--portname", default=None, help="Port name (e.g., port0) used to derive index")

    p_enc_clear = sp.add_parser("encap-clear", help="Clear/disable tx encapsulation for a port stream")
    p_enc_clear.add_argument("--port-index", type=int, default=None, help="Port index (preferred)")
    p_enc_clear.add_argument("--portname", default=None, help="Port name (e.g., port0) used to derive index")

    p_enc_set = sp.add_parser("encap-set", help="Configure tx encapsulation for a port stream")
    p_enc_set.add_argument("--port-index", type=int, default=None, help="Port index (preferred)")
    p_enc_set.add_argument("--portname", default=None, help="Port name (e.g., port0) used to derive index")

    p_enc_set.add_argument("--type", required=True, choices=["none", "vxlan", "gre", "qinq", "erspan"], help="Encap type")
    p_enc_set.add_argument("--disable", action="store_true", help="Disable encapsulation (equivalent to type=none)")

    p_enc_set.add_argument("--mode", default="try_prepend",
                           choices=["try_prepend", "force_prepend", "force_chain"],
                           help="Encap apply mode")
    p_enc_set.add_argument("--oversize-policy", default="drop",
                           choices=["drop", "allow", "fragment"],
                           help="Oversize behavior relative to MTU")
    p_enc_set.add_argument("--outer-csum-hw-offload", action="store_true",
                           help="Request outer checksum HW offload (if implemented in datapath)")

    p_enc_set.add_argument("--max-inner-l2-len", type=int, default=None,
                           help="Optional: max inner L2 len for validation (bytes)")

    # Outer header args (required for vxlan/gre/erspan)
    p_enc_set.add_argument("--outer-src-mac", default=None, help="Outer src MAC aa:bb:cc:dd:ee:ff")
    p_enc_set.add_argument("--outer-dst-mac", default=None, help="Outer dst MAC aa:bb:cc:dd:ee:ff")
    p_enc_set.add_argument("--outer-src-ip", default=None, help="Outer src IPv4 (VTEP) e.g. 10.0.0.1")
    p_enc_set.add_argument("--outer-dst-ip", default=None, help="Outer dst IPv4 (VTEP) e.g. 10.0.0.2")
    p_enc_set.add_argument("--outer-ttl", type=int, default=64, help="Outer IPv4 TTL")
    p_enc_set.add_argument("--outer-dscp", type=int, default=0, help="Outer IPv4 DSCP (0..63)")
    p_enc_set.add_argument("--outer-df", action="store_true", default=True, help="Set DF bit on outer IPv4")
    p_enc_set.add_argument("--outer-no-df", dest="outer_df", action="store_false", help="Clear DF bit on outer IPv4")

    # Optional underlay VLAN (outer L2 tags)
    p_enc_set.add_argument("--outer-vlan-mode", default="none", choices=["none", "8021q", "qinq"],
                           help="Underlay VLAN tags on outer Ethernet header")
    p_enc_set.add_argument("--outer-vlan-id", type=int, default=None, help="Underlay 802.1Q VLAN ID")
    p_enc_set.add_argument("--outer-vlan-pcp", type=int, default=0, help="Underlay 802.1Q PCP (0..7)")
    p_enc_set.add_argument("--outer-vlan-dei", type=int, default=0, help="Underlay 802.1Q DEI (0..1)")

    p_enc_set.add_argument("--outer-s-vlan-id", type=int, default=None, help="Underlay QinQ S-VLAN ID")
    p_enc_set.add_argument("--outer-s-vlan-pcp", type=int, default=0, help="Underlay QinQ S-PCP")
    p_enc_set.add_argument("--outer-s-vlan-dei", type=int, default=0, help="Underlay QinQ S-DEI")
    p_enc_set.add_argument("--outer-c-vlan-id", type=int, default=None, help="Underlay QinQ C-VLAN ID")
    p_enc_set.add_argument("--outer-c-vlan-pcp", type=int, default=0, help="Underlay QinQ C-PCP")
    p_enc_set.add_argument("--outer-c-vlan-dei", type=int, default=0, help="Underlay QinQ C-DEI")

    # VXLAN
    p_enc_set.add_argument("--vni", type=int, default=None, help="VXLAN VNI (0..16777215)")
    p_enc_set.add_argument("--udp-dst-port", type=int, default=4789, help="VXLAN UDP dst port (default 4789)")
    p_enc_set.add_argument("--udp-srcport-mode", default="fixed",
                           choices=["fixed", "hash_inner_l2", "hash_inner_5tuple"],
                           help="VXLAN UDP src port derivation")
    p_enc_set.add_argument("--udp-src-port", type=int, default=5555, help="VXLAN UDP src port (fixed mode)")
    p_enc_set.add_argument("--udp-checksum", action="store_true", help="Enable VXLAN UDP checksum (if supported)")

    # GRE
    p_enc_set.add_argument("--gre-teb-mode", action="store_true", default=True,
                           help="GRE TEB mode (Ethernet-over-GRE). Default true.")
    p_enc_set.add_argument("--gre-ip-mode", dest="gre_teb_mode", action="store_false",
                           help="GRE IP payload mode (IP-over-GRE).")
    p_enc_set.add_argument("--gre-key", type=int, default=None, help="GRE key (enables key_present)")
    p_enc_set.add_argument("--gre-seq-start", type=int, default=None, help="GRE sequence start (enables seq_present)")
    p_enc_set.add_argument("--gre-csum", action="store_true", help="Enable GRE checksum present flag")

    # QinQ
    p_enc_set.add_argument("--qinq-mode", default="push", choices=["push", "replace", "push_if_untagged"],
                           help="QinQ insertion mode")
    p_enc_set.add_argument("--s-vlan-id", type=int, default=None, help="QinQ S-VLAN ID (outer tag)")
    p_enc_set.add_argument("--s-pcp", type=int, default=0, help="QinQ S-PCP (0..7)")
    p_enc_set.add_argument("--s-dei", type=int, default=0, help="QinQ S-DEI (0..1)")
    p_enc_set.add_argument("--c-vlan-id", type=int, default=None, help="QinQ C-VLAN ID (inner tag)")
    p_enc_set.add_argument("--c-pcp", type=int, default=0, help="QinQ C-PCP (0..7)")
    p_enc_set.add_argument("--c-dei", type=int, default=0, help="QinQ C-DEI (0..1)")
    p_enc_set.add_argument("--preserve-existing-vlan", action="store_true",
                           help="If packet already VLAN-tagged, preserve existing VLAN stack (if supported)")

    # ERSPAN
    p_enc_set.add_argument("--erspan-type", default="II", choices=["II", "III"], help="ERSPAN header type")
    p_enc_set.add_argument("--session-id", type=int, default=None, help="ERSPAN session/span id")
    p_enc_set.add_argument("--erspan-seq-start", type=int, default=None, help="ERSPAN GRE seq start (enables sequence_present)")

    return p


def main() -> int:
    args = build_parser().parse_args()

    ctl = WpsControlClient(port=args.port, hostip=args.hostip)
    traffic = WprTrafficClient(ctl)

    try:
        if args.command == "ports":
            reply = traffic.get_port_list()
            display_ports(reply)
            return 0

        if args.command == "tx":
            reply = traffic.port_tx_ctl(args.portname, args.cmd)
            display_generic_reply("TX Control Reply", reply)
            return 0

        if args.command == "pcaps":
            reply = traffic.get_loaded_pcaps_list()
            display_loaded_pcaps(reply)
            return 0

        if args.command == "load":
            reply = traffic.load_pcap_file(args.filename)
            display_generic_reply("Load PCAP Reply", reply)
            if "slotid" in reply:
                print(f"Loaded '{args.filename}' into slotid={reply['slotid']}")
            elif "slot_id" in reply:
                print(f"Loaded '{args.filename}' into slotid={reply['slot_id']}")
            return 0

        if args.command == "assign":
            pace_mode = _resolve_pace_mode(args.pace_mode)
            start_mode = _resolve_start_mode(args.start_mode)
            reply = traffic.assign_port_slot(
                port=args.portname,
                slotid=args.slotid,
                pace_mode=pace_mode,
                start_mode=start_mode,
                fixed_index=args.fixed_index,
                replay_window_sec=args.replay_window_sec,
            )
            display_generic_reply("Assign Port Slot Reply", reply)
            return 0

        if args.command == "vcs":
            reply = traffic.set_port_stream_vcs(args.portname, args.num_vcs)
            display_generic_reply("Set Port Stream VCs Reply", reply)
            return 0

        if args.command == "rate":
            reply = traffic.set_target_rate(args.portname, args.kind, args.value)
            display_generic_reply("Set Target Rate Reply", reply)
            return 0

        if args.command == "encap-get":
            port_index = _pick_port_index(args.port_index, args.portname)
            reply = traffic.tx_encap_get(port_index)
            display_encap_reply("Encap Get Reply", reply)
            return 0

        if args.command == "encap-clear":
            port_index = _pick_port_index(args.port_index, args.portname)
            reply = traffic.tx_encap_clear(port_index)
            display_encap_reply("Encap Clear Reply", reply)
            return 0

        if args.command == "encap-set":
            port_index = _pick_port_index(args.port_index, args.portname)
            payload = build_encap_payload_from_cli(args)
            reply = traffic.tx_encap_set(port_index, payload)
            display_encap_reply("Encap Set Reply", reply)
            return 0

        raise RuntimeError(f"Unknown command: {args.command}")

    except (WpsControlError, ValueError) as e:
        print(f"ERROR: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
