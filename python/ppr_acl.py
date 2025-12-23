#!/usr/bin/env python3
"""
ppr_acl.py - Friendly Python wrapper for PPR ACL JSON RPC API.

Depends on:
  - WpsControlClient from your ppr_cli.py (adjust import as needed)
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import List, Tuple, Union, Optional, Dict, Any
import socket
import argparse
from prettytable import PrettyTable

from ppr_cli import WpsControlClient, WpsControlError  # adjust path if needed


# ---------------------------------------------------------------------------
# Basic mappings / helpers
# ---------------------------------------------------------------------------

# These must match your C enum ppr_flow_action_kind_t
ACTION_NAME_TO_ID: Dict[str, int] = {
    "FLOW_ACT_NOOP": 0, 
    "FLOW_ACT_DROP": 1,       
    "FLOW_ACT_MODIFY_SRCMAC": 2,
    "FLOW_ACT_MODIFY_SRCIP": 3,   
    "FLOW_ACT_MODIFY_SRCPORT": 4,
    "FLOW_ACT_MODIFY_SRC_ALL" : 5, 
    "FLOW_ACT_MODIFY_DSTMAC" : 6,  
    "FLOW_ACT_MODIFY_DSTIP" : 7,   
    "FLOW_ACT_MODIFY_DSTPORT": 8, 
    "FLOW_ACT_MODIFY_DST_ALL": 9, 
    "FLOW_ACT_MODIFY_ALL" : 10,     
ACTION_ID_TO_NAME: Dict[int, str] = {v: k for k, v in ACTION_NAME_TO_ID.items()}


def _proto_to_num(proto: Union[int, str]) -> int:
    """Map protocol name or number to an integer for 'proto' field."""
    if isinstance(proto, int):
        return proto
    if not proto:
        return 0
    name = proto.lower()
    if name in ("any", "0"):
        return 0
    try:
        return socket.getprotobyname(name)  # tcp, udp, icmp, etc.
    except OSError:
        raise ValueError(f"Unknown protocol '{proto}'")


def _parse_cidr_or_ip(s: str) -> Tuple[str, int]:
    """
    Parse '10.0.0.0/24' or '10.0.0.1' and return (ip_str, prefix_len).
    For bare IPs, prefix = /32 (/128 for v6).
    """
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        return str(net.network_address), net.prefixlen
    else:
        ip = ipaddress.ip_address(s)
        if isinstance(ip, ipaddress.IPv4Address):
            return str(ip), 32
        else:
            return str(ip), 128


def _parse_port_range(
    value: Union[int, str, Tuple[int, int]]
) -> Tuple[int, int]:
    """
    Accept:
      - int -> (value, value)
      - '80-90' or '80:90' -> (80, 90)
      - (80, 90) -> (80, 90)
      - None -> wildcard (0, 65535)
    """
    if value is None:
        return 0, 65535

    if isinstance(value, int):
        return value, value

    if isinstance(value, tuple) and len(value) == 2:
        lo, hi = value
        return int(lo), int(hi)

    if isinstance(value, str):
        if "-" in value:
            lo, hi = value.split("-", 1)
        elif ":" in value:
            lo, hi = value.split(":", 1)
        else:
            # single port string
            p = int(value)
            return p, p
        return int(lo), int(hi)

    raise ValueError(f"Invalid port range: {value!r}")


def _parse_vlan_range(
    value: Union[int, str, Tuple[int, int], None]
) -> Tuple[int, int]:
    """Same idea as ports, but default wildcard is 0..0xFFFF."""
    if value is None:
        return 0, 0xFFFF
    return _parse_port_range(value)


# ---------------------------------------------------------------------------
# Dataclasses representing actions and rules
# ---------------------------------------------------------------------------

@dataclass
class AclAction:
    """High-level ACL action description."""
    # default must exist in ACTION_NAME_TO_ID
    default_policy: Union[int, str] = "FLOW_ACT_DROP"

    def to_wire(self) -> Dict[str, Any]:
        """Convert to the JSON shape expected by ppr_acl_action_from_json()."""
        if isinstance(self.default_policy, str):
            name = self.default_policy.upper()
            if name not in ACTION_NAME_TO_ID:
                raise ValueError(f"Unknown default_policy '{self.default_policy}'")
            default_policy_id = ACTION_NAME_TO_ID[name]
        else:
            default_policy_id = int(self.default_policy)

        return {
            "default_policy": default_policy_id,
        }

    @classmethod
    def from_wire(cls, data: Dict[str, Any]) -> "AclAction":
        dp = int(data.get("default_policy", 0))
        name = ACTION_ID_TO_NAME.get(dp, str(dp))
        return cls(
            default_policy=name,
        )


@dataclass
class IPv4Rule:
    """User-friendly IPv4 ACL rule."""
    src: str = "0.0.0.0/0"
    dst: str = "0.0.0.0/0"
    src_ports: Union[int, str, Tuple[int, int], None] = None
    dst_ports: Union[int, str, Tuple[int, int], None] = None
    # IMPORTANT: in_ports is a *string of names* like "portf1:portf2" or "portf1-portf2"
    in_ports: Optional[str] = None
    proto: Union[int, str] = "any"

    tenant_id: Union[int, Tuple[int, int]] = 0
    priority: int = 0
    rule_id: Optional[int] = None  # assigned by C side, usually

    action: AclAction = field(default_factory=AclAction)

    def to_wire(self) -> Dict[str, Any]:
        src_ip, src_prefix = _parse_cidr_or_ip(self.src)
        dst_ip, dst_prefix = _parse_cidr_or_ip(self.dst)

        src_lo, src_hi = _parse_port_range(self.src_ports)
        dst_lo, dst_hi = _parse_port_range(self.dst_ports)

        if isinstance(self.tenant_id, tuple):
            tenant_lo, tenant_hi = self.tenant_id
        else:
            tenant_lo = tenant_hi = int(self.tenant_id)

        cfg: Dict[str, Any] = {
            "tenant_ids": str(tenant_lo) + ":" + str(tenant_hi),
            "src": src_ip,
            "dst": dst_ip,
            "src_prefix": src_prefix,
            "dst_prefix": dst_prefix,
            "src_ports" : str(src_lo) + ":" + str(src_hi),
            "dst_ports" : str(dst_lo) + ":" + str(dst_hi),
            "proto": _proto_to_num(self.proto),
            "priority": int(self.priority),
        }

        # Only include in_ports if user specified it. It is a string of names.
        if self.in_ports:
            cfg["in_ports"] = self.in_ports

        if self.rule_id is not None:
            cfg["rule_id"] = int(self.rule_id)

        cfg["action"] = self.action.to_wire()
        return cfg


@dataclass
class IPv6Rule:
    """User-friendly IPv6 ACL rule."""
    src: str = "::/0"
    dst: str = "::/0"
    src_ports: Union[int, str, Tuple[int, int], None] = None
    dst_ports: Union[int, str, Tuple[int, int], None] = None
    # Again, names string like "portf1:portf2"
    in_ports: Optional[str] = None
    proto: Union[int, str] = "any"

    tenant_id: Union[int, Tuple[int, int]] = 0
    priority: int = 0
    rule_id: Optional[int] = None

    action: AclAction = field(default_factory=AclAction)

    def to_wire(self) -> Dict[str, Any]:
        src_ip, src_prefix = _parse_cidr_or_ip(self.src)
        dst_ip, dst_prefix = _parse_cidr_or_ip(self.dst)

        src_lo, src_hi = _parse_port_range(self.src_ports)
        dst_lo, dst_hi = _parse_port_range(self.dst_ports)

        if isinstance(self.tenant_id, tuple):
            tenant_lo, tenant_hi = self.tenant_id
        else:
            tenant_lo = tenant_hi = int(self.tenant_id)

        cfg: Dict[str, Any] = {
            "tenant_ids": str(tenant_lo) + ":" + str(tenant_hi),
            "src": src_ip,
            "dst": dst_ip,
            "src_prefix": src_prefix,
            "dst_prefix": dst_prefix,
            "src_ports" : str(src_lo) + ":" + str(src_hi),
            "dst_ports" : str(dst_lo) + ":" + str(dst_hi),
            "proto": _proto_to_num(self.proto),
            "priority": int(self.priority),
        }

        if self.in_ports:
            cfg["in_ports"] = self.in_ports

        if self.rule_id is not None:
            cfg["rule_id"] = int(self.rule_id)

        cfg["action"] = self.action.to_wire()
        return cfg


@dataclass
class L2Rule:
    """User-friendly L2 ACL rule."""
    src_mac: str = "00:00:00:00:00:00"
    dst_mac: str = "00:00:00:00:00:00"
    ether_type: Optional[int] = None  # None = wildcard

    # Names string for ingress ports as well (if you want the same behavior)
    in_ports: Optional[str] = None
    outer_vlan: Union[int, str, Tuple[int, int], None] = None
    inner_vlan: Union[int, str, Tuple[int, int], None] = None
    is_mac_match: bool = True

    tenant_id: Union[int, Tuple[int, int]] = 0
    priority: int = 0
    rule_id: Optional[int] = None

    action: AclAction = field(default_factory=AclAction)

    def to_wire(self) -> Dict[str, Any]:
        outer_lo, outer_hi = _parse_vlan_range(self.outer_vlan)
        inner_lo, inner_hi = _parse_vlan_range(self.inner_vlan)

        if isinstance(self.tenant_id, tuple):
            tenant_lo, tenant_hi = self.tenant_id
        else:
            tenant_lo = tenant_hi = int(self.tenant_id)

        cfg: Dict[str, Any] = {
            "tenant_ids": str(tenant_lo) + ":" + str(tenant_hi),
            "outer_vlans": str(outer_lo) + ":" + str(outer_hi),
            "inner_vlans": str(inner_lo) + ":" + str(inner_hi),
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "is_mac_match": bool(self.is_mac_match),
            "priority": int(self.priority),
            "ether_type": int(self.ether_type) if self.ether_type is not None else 0,
        }

        # Optional in_ports string of names for L2 too
        if self.in_ports:
            cfg["in_ports"] = self.in_ports

        if self.rule_id is not None:
            cfg["rule_id"] = int(self.rule_id)

        cfg["action"] = self.action.to_wire()
        return cfg


# ---------------------------------------------------------------------------
# High-level client wrapper
# ---------------------------------------------------------------------------

class WpsAclClient:
    """
    High-level wrapper around the ACL JSON RPC commands.
    """

    CMD_GET_DB = "ppr_cmd_get_acl_db"
    CMD_ADD_RULE = "ppr_cmd_add_acl_rule"
    CMD_UPDATE_RULE = "ppr_cmd_update_acl_rule"
    CMD_DELETE_RULE = "ppr_cmd_delete_acl_rule"
    CMD_CHECK_STATUS = "ppr_cmd_check_acl_status"
    CMD_COMMIT = "ppr_cmd_acl_db_commit"

    def __init__(self, ctl: WpsControlClient) -> None:
        self.ctl = ctl

    # ---- Basic operations -------------------------------------------------

    def get_db(self) -> Dict[str, Any]:
        """Return raw ACL DB as provided by C API."""
        return self.ctl.call(self.CMD_GET_DB)

    def check_status(self) -> Dict[str, Any]:
        """Return rule counts and dirty flags."""
        return self.ctl.call(self.CMD_CHECK_STATUS)

    def commit(self) -> None:
        """Trigger ACL DB commit/build + runtime swap."""
        self.ctl.call(self.CMD_COMMIT)

    # ---- Add rules --------------------------------------------------------

    def add_ipv4_rule(self, rule: IPv4Rule) -> int:
        """Add IPv4 rule and return assigned_rule_id."""
        payload = {
            "rule_type": "ipv4",
            "rule_cfg": rule.to_wire(),
        }
        reply = self.ctl.call(self.CMD_ADD_RULE, args=payload)
        return int(reply.get("assigned_rule_id", -1))

    def add_ipv6_rule(self, rule: IPv6Rule) -> int:
        payload = {
            "rule_type": "ipv6",
            "rule_cfg": rule.to_wire(),
        }
        reply = self.ctl.call(self.CMD_ADD_RULE, args=payload)
        return int(reply.get("assigned_rule_id", -1))

    def add_l2_rule(self, rule: L2Rule) -> int:
        payload = {
            "rule_type": "l2",
            "rule_cfg": rule.to_wire(),
        }
        reply = self.ctl.call(self.CMD_ADD_RULE, args=payload)
        return int(reply.get("assigned_rule_id", -1))

    # ---- Update rules -----------------------------------------------------

    def update_ipv4_rule(self, rule_id: int, rule: IPv4Rule) -> None:
        payload = {
            "rule_type": "ipv4",
            "rule_id": int(rule_id),
            "rule_cfg": rule.to_wire(),
        }
        self.ctl.call(self.CMD_UPDATE_RULE, args=payload)

    def update_ipv6_rule(self, rule_id: int, rule: IPv6Rule) -> None:
        payload = {
            "rule_type": "ipv6",
            "rule_id": int(rule_id),
            "rule_cfg": rule.to_wire(),
        }
        self.ctl.call(self.CMD_UPDATE_RULE, args=payload)

    def update_l2_rule(self, rule_id: int, rule: L2Rule) -> None:
        payload = {
            "rule_type": "l2",
            "rule_id": int(rule_id),
            "rule_cfg": rule.to_wire(),
        }
        self.ctl.call(self.CMD_UPDATE_RULE, args=payload)

    # ---- Delete rules -----------------------------------------------------

    def delete_ipv4_rule(self, rule_id: int) -> None:
        payload = {"rule_type": "ipv4", "rule_id": int(rule_id)}
        self.ctl.call(self.CMD_DELETE_RULE, args=payload)

    def delete_ipv6_rule(self, rule_id: int) -> None:
        payload = {"rule_type": "ipv6", "rule_id": int(rule_id)}
        self.ctl.call(self.CMD_DELETE_RULE, args=payload)

    def delete_l2_rule(self, rule_id: int) -> None:
        payload = {"rule_type": "l2", "rule_id": int(rule_id)}
        self.ctl.call(self.CMD_DELETE_RULE, args=payload)

    # ---- Convenience listing helpers -------------------------------------

    def list_ipv4_rules(self) -> List[Dict[str, Any]]:
        db = self.get_db()
        return list(db.get("ipv4_rules", []))

    def list_ipv6_rules(self) -> List[Dict[str, Any]]:
        db = self.get_db()
        return list(db.get("ipv6_rules", []))

    def list_l2_rules(self) -> List[Dict[str, Any]]:
        db = self.get_db()
        return list(db.get("l2_rules", []))


#----------------------------------------------------------------------------#
def display_acl_status(json_dict):
    table = PrettyTable()

    header = ["ACL Type", "Rule Count", "Dirty"]
    table.field_names = header

    ipv4_count = json_dict.get("ipv4_rule_count", 0)
    ipv6_count = json_dict.get("ipv6_rule_count", 0)
    l2_count = json_dict.get("l2_rule_count", 0)
    db_dirty = json_dict.get("db_dirty", False)
    ipv4_dirty = json_dict.get("ipv4_dirty", False)
    ipv6_dirty = json_dict.get("ipv6_dirty", False)
    l2_dirty = json_dict.get("l2_dirty", False)

    table.add_row(["IPv4 Table", ipv4_count, ipv4_dirty])
    table.add_row(["IPv6 Table", ipv6_count, ipv6_dirty])
    table.add_row(["L2 Table", l2_count, l2_dirty])
    table.add_row(["Total Database", ipv4_count + ipv6_count + l2_count, db_dirty])

    print("ACL Status:")
    print(table)
    print("\n")


def display_acl_rules(ruleset_type, json_dict):


    table = PrettyTable()
    if ruleset_type == "ipv4":
        print("IPv4 ACL Table:")
        hdr = ["Rule ID", "Tenant ID", "Priority", "Src IP", "Dst IP", "Src Ports",
               "Dst Ports", "In Ports", "Proto", "Action", "Total Flows", "Active Flows"]
        table.field_names = hdr
        results = []
        for entries in json_dict:
            rule_id = entries.get("rule_id", "")
            tenant_ids = entries.get("tenant_ids","")
            priority = entries.get("priority", "")
            src_ip = f"{entries.get('src', '')}/{entries.get('src_prefix', '')}"
            dst_ip = f"{entries.get('dst', '')}/{entries.get('dst_prefix', '')}"
            src_ports = entries.get("src_ports", "")
            dst_ports = entries.get("dst_ports", "")
            in_ports = entries.get("in_ports", "")
            proto = entries.get("proto", "")
            action = entries.get("action", {}).get("default_policy", 0)
            total_flows = entries.get("total_flows", 0)
            active_flows = entries.get("active_flows", 0)

            results.append([rule_id, tenant_ids, priority, src_ip, dst_ip,
                            src_ports, dst_ports, in_ports, proto, action,
                            egress_targets, lb_groups, total_flows, active_flows])

        sorted_rows = sorted(results, key=lambda x: x[2], reverse=True)
        for row in sorted_rows:
            table.add_row(row)

        print(table)
        print("\n")

    elif ruleset_type == "ipv6":
        print("IPv6 ACL Table:")
        hdr = ["Rule ID", "Tenant ID", "Priority", "Src IP", "Dst IP", "Src Ports",
               "Dst Ports", "In Ports", "Proto", "Action", "Total Flows", "Active Flows"]
        table.field_names = hdr
        results = []
        for entries in json_dict:
            rule_id = entries.get("rule_id", "")
            tenant_ids = entries.get("tenant_ids","")
            priority = entries.get("priority", "")
            src_ip = f"{entries.get('src', '')}/{entries.get('src_prefix', '')}"
            dst_ip = f"{entries.get('dst', '')}/{entries.get('dst_prefix', '')}"
            src_ports = entries.get("src_ports", "")
            dst_ports = entries.get("dst_ports", "")
            in_ports = entries.get("in_ports", "")
            proto = entries.get("proto", "")
            action = entries.get("action", {}).get("default_policy", 0)
            total_flows = entries.get("total_flows", 0)
            active_flows = entries.get("active_flows", 0)


            results.append([rule_id, tenant_ids, priority, src_ip, dst_ip,
                            src_ports, dst_ports, in_ports, proto, action,
                            egress_targets, lb_groups, total_flows, active_flows])

        sorted_rows = sorted(results, key=lambda x: x[2], reverse=True)
        for row in sorted_rows:
            table.add_row(row)

        print(table)
        print("\n")

    elif ruleset_type == "l2":
        print("L2 ACL Table:")
        hdr = ["Rule ID", "Tenant ID", "Priority", "Is MAC Match", "Src MAC", "Dst MAC",
               "Ether Type", "In Ports", "Outer VLAN", "Inner VLAN",
               "Action", "Total Flows", "Active Flows"]
        table.field_names = hdr

        results = []
        for entries in json_dict:
            rule_id = entries.get("rule_id", "")
            tenant_ids = entries.get("tenant_ids","")
            priority = entries.get("priority", "")
            is_mac_match = entries.get("is_mac_match", "")
            src_mac = entries.get("src_mac", "")
            dst_mac = entries.get("dst_mac", "")
            ether_type = entries.get("ether_type", "")
            in_ports = entries.get("in_ports", "")
            outer_vlans = entries.get("outer_vlans","")
            inner_vlans = entries.get("inner_vlans","")
            action = entries.get("action", {}).get("default_policy", 0)
            total_flows = entries.get("total_flows", 0)
            active_flows = entries.get("active_flows", 0)


            results.append([rule_id, tenant_ids, priority, is_mac_match,
                            src_mac, dst_mac, ether_type, in_ports, outer_vlans,
                            inner_vlans, action, egress_targets, lb_groups, total_flows, active_flows])

        sorted_rows = sorted(results, key=lambda x: x[2], reverse=True)
        for row in sorted_rows:
            table.add_row(row)
        print(table)
        print("\n")

    else:
        print(f"Unknown ruleset type '{ruleset_type}' for display")
        return


def _build_ipv4_rule_from_args(ns: argparse.Namespace) -> IPv4Rule:
    action = AclAction(
        default_policy=ns.action,
    )

    rule = IPv4Rule(
        src=ns.src or "0.0.0.0/0",
        dst=ns.dst or "0.0.0.0/0",
        src_ports=ns.src_ports,
        dst_ports=ns.dst_ports,
        # in_ports stays as the raw string ("portf1:portf2" or "portf1-portf2")
        in_ports=ns.in_ports,
        proto=ns.proto or "any",
        tenant_id=ns.tenant if ns.tenant is not None else 0,
        priority=ns.priority if ns.priority is not None else 0,
        action=action,
    )
    return rule


def _build_ipv6_rule_from_args(ns: argparse.Namespace) -> IPv6Rule:
    action = AclAction(
        default_policy=ns.action,
    )

    rule = IPv6Rule(
        src=ns.src or "::/0",
        dst=ns.dst or "::/0",
        src_ports=ns.src_ports,
        dst_ports=ns.dst_ports,
        in_ports=ns.in_ports,
        proto=ns.proto or "any",
        tenant_id=ns.tenant if ns.tenant is not None else 0,
        priority=ns.priority if ns.priority is not None else 0,
        action=action,
    )
    return rule


def _build_l2_rule_from_args(ns: argparse.Namespace) -> L2Rule:
    action = AclAction(
        default_policy=ns.action,
    )

    rule = L2Rule(
        src_mac=ns.src_mac or "00:00:00:00:00:00",
        dst_mac=ns.dst_mac or "00:00:00:00:00:00",
        ether_type=ns.ether_type,
        in_ports=ns.in_ports,
        outer_vlan=ns.outer_vlan,
        inner_vlan=ns.inner_vlan,
        is_mac_match=ns.is_mac_match,
        tenant_id=ns.tenant if ns.tenant is not None else 0,
        priority=ns.priority if ns.priority is not None else 0,
        action=action,
    )
    return rule


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wirepath Switch ACL Manager Client")

    parser.add_argument("-p", "--port", type=int, default=9000, help="RPC Server Port")
    parser.add_argument("-i", "--hostip", type=str, default="localhost", help="RPC Server Address")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -------- list --------
    p_list = subparsers.add_parser("list", help="List ACL rules")
    p_list.add_argument(
        "--family",
        choices=["ipv4", "ipv6", "l2", "all"],
        default="all",
        help="Which rules to list",
    )

    # -------- add-ipv4 --------
    p_add4 = subparsers.add_parser("add-ipv4", help="Add an IPv4 ACL rule")
    p_add4.add_argument("--src", help="Source CIDR, e.g. 10.0.0.0/24")
    p_add4.add_argument("--dst", help="Destination CIDR, e.g. 192.168.1.10/32")
    p_add4.add_argument("--src-ports", help="Source ports, e.g. 80, 1000-2000, 80:90")
    p_add4.add_argument("--dst-ports", help="Destination ports")
    # IMPORTANT: names string
    p_add4.add_argument("--in-ports", help="Ingress ports as names, e.g. 'portf1:portf2' or 'portf1-portf2'")
    p_add4.add_argument("--proto", help="Protocol name or number (tcp, udp, icmp, 6, ...)")
    p_add4.add_argument("--tenant", type=int, help="Tenant ID (single value)")
    p_add4.add_argument("--priority", type=int, help="Priority (higher wins)")

    p_add4.add_argument(
        "--action",
        default="FLOW_ACT_FWD_PORT",
        help="Action (FLOW_ACT_DROP, FLOW_ACT_FWD_PORT, FLOW_ACT_FWD_LB, ...)",
    )

    # -------- add-ipv6 --------
    p_add6 = subparsers.add_parser("add-ipv6", help="Add an IPv6 ACL rule")
    p_add6.add_argument("--src", help="Source CIDR, e.g. 2001:db8::/64")
    p_add6.add_argument("--dst", help="Destination CIDR")
    p_add6.add_argument("--src-ports", help="Source ports, e.g. 80, 1000-2000, 80:90")
    p_add6.add_argument("--dst-ports", help="Destination ports")
    p_add6.add_argument("--in-ports", help="Ingress ports as names, e.g. 'portf1:portf2'")
    p_add6.add_argument("--proto", help="Protocol name or number (tcp, udp, icmpv6, 58, ...)")
    p_add6.add_argument("--tenant", type=int, help="Tenant ID")
    p_add6.add_argument("--priority", type=int, help="Priority")

    p_add6.add_argument(
        "--action",
        default="FLOW_ACT_FWD_PORT",
        help="Action (FLOW_ACT_DROP, FLOW_ACT_FWD_PORT, FLOW_ACT_FWD_LB, ...)",
    )

    # -------- add-l2 --------
    p_addl2 = subparsers.add_parser("add-l2", help="Add an L2 ACL rule")
    p_addl2.add_argument("--src-mac", help="Source MAC, e.g. 00:11:22:33:44:55")
    p_addl2.add_argument("--dst-mac", help="Destination MAC")
    p_addl2.add_argument("--ether-type", type=lambda x: int(x, 0), help="EtherType (0x0800, 0x86dd, ...)")
    p_addl2.add_argument("--in-ports", help="Ingress ports as names, e.g. 'portf1:portf2'")
    p_addl2.add_argument("--outer-vlan", help="Outer VLAN or VLAN range, e.g. 10, 10-20")
    p_addl2.add_argument("--inner-vlan", help="Inner VLAN or VLAN range")
    p_addl2.add_argument("--no-mac-match", action="store_true", help="Disable MAC match (is_mac_match=0)")

    p_addl2.add_argument("--tenant", type=int, help="Tenant ID")
    p_addl2.add_argument("--priority", type=int, help="Priority")

    p_addl2.add_argument(
        "--action",
        default="FLOW_ACT_FWD_PORT",
        help="Action (FLOW_ACT_DROP, FLOW_ACT_FWD_PORT, FLOW_ACT_FWD_LB, ...)",
    )

    # -------- delete --------
    p_del = subparsers.add_parser("delete", help="Delete a rule by type and ID")
    p_del.add_argument("family", choices=["ipv4", "ipv6", "l2"], help="Rule family")
    p_del.add_argument("rule_id", type=int, help="Rule ID to delete")

    # -------- commit --------
    subparsers.add_parser("commit", help="Commit ACL DB (rebuild + swap)")

    # --------------------------------------------------------------------- #
    # Parse + dispatch
    # --------------------------------------------------------------------- #
    args = parser.parse_args()

    ctl = WpsControlClient(port=args.port, hostip=args.hostip)
    acl = WpsAclClient(ctl)

    if args.command == "list":
        display_acl_status(acl.check_status())

        if args.family in ("ipv4", "all"):
            display_acl_rules("ipv4", acl.list_ipv4_rules())
        if args.family in ("ipv6", "all"):
            display_acl_rules("ipv6", acl.list_ipv6_rules())
        if args.family in ("l2", "all"):
            display_acl_rules("l2", acl.list_l2_rules())

    elif args.command == "add-ipv4":
        rule = _build_ipv4_rule_from_args(args)
        rule_id = acl.add_ipv4_rule(rule)
        print(f"Added IPv4 rule id={rule_id}")

    elif args.command == "add-ipv6":
        rule = _build_ipv6_rule_from_args(args)
        rule_id = acl.add_ipv6_rule(rule)
        print(f"Added IPv6 rule id={rule_id}")

    elif args.command == "add-l2":
        # translate no-mac-match → bool
        args.is_mac_match = not args.no_mac_match
        rule = _build_l2_rule_from_args(args)
        rule_id = acl.add_l2_rule(rule)
        print(f"Added L2 rule id={rule_id}")

    elif args.command == "delete":
        if args.family == "ipv4":
            acl.delete_ipv4_rule(args.rule_id)
        elif args.family == "ipv6":
            acl.delete_ipv6_rule(args.rule_id)
        else:
            acl.delete_l2_rule(args.rule_id)
        print(f"Deleted {args.family} rule id={args.rule_id}")

    elif args.command == "commit":
        acl.commit()
        print("ACL DB committed.")
