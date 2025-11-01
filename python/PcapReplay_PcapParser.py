'''
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: PacketSmith_Pcap.py
Description: Scapy based API for managing loading, pre-processing, and partitioning of Pcap files 

'''


from scapy.all import Ether,IP, IPv6, TCP, UDP, SCTP, ICMP, BOOTP,DHCP,DNS, DNSQR, DNSRR, Raw, wrpcap, rdpcap
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6Unknown
from ipaddress import ip_address, ip_network, IPv4Address
import hashlib
import argparse
import json
import sys 
from pathlib import Path
import os
import datetime
from concurrent.futures import ProcessPoolExecutor
import random 
import time 
from typing import List, Tuple, Union, Dict,Optional,Any
from faker import Faker
import zlib

#simple flow table class to tag flows and assign them to output files 
class PReplayFlowTable():
    flow_entry = {"flow_id": "",
                  "output_file_no": "",
                  "pkt_cnt": 0}
    
    def __init__(self):
        self.flowtable  = {}
        self.entries    = 0

    def add_entry(self, flowid):
        flow_entry = {}
        flow_entry["flow_id"] = str(flowid)
        flow_entry["pkt_cnt"] = 1
        flow_entry["action_struct"] = { "kind"   : 0,
                                        "src_ip" : flowid[0],
                                        "dst_ip" : flowid[1],
                                        "src_port" : flowid[3],
                                        "dst_port" : flowid[4],
                                        "proto" : flowid[2],
                                        "a_src_mac" : "-1",
                                        "a_dst_mac" : "-1",
                                        "a_src_ip" : "-1",
                                        "a_dst_ip" : "-1",
                                        "a_src_port" : -1,
                                        "a_dst_port" : -1}

        #if flow already hits in table 
        if str(flowid) in self.flowtable:
            self.flowtable[str(flowid)]["pkt_cnt"] = self.flowtable[str(flowid)]["pkt_cnt"] + 1

        # if new flow, add to dit
        else:
            #add entry and increment
            self.flowtable[str(flowid)] = flow_entry
            self.entries = self.entries + 1
    
    def get_entry(self,flowid): 

        if str(flowid) not in self.flowtable: 
            print("error flowid not found in table")
            return -1
        
        else: 
            return self.flowtable[str(flowid)]

class PReplayPcapParser():
    def __init__(self): 
        self.flowtable = PReplayFlowTable()
        self.pcap_lib = []

        self.default_rss_key = bytes([
        0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
        0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
        0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
        0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
        0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA
        ])

    def get_l4_info(self, pkt):
        # TCP/UDP/SCTP first (straightforward)
        if TCP in pkt:
            l4 = pkt[TCP];  
            return (6,  l4.sport, l4.dport)
        if UDP in pkt:
            l4 = pkt[UDP];  
            return (17, l4.sport, l4.dport)
        if SCTP in pkt:
            l4 = pkt[SCTP]; 
            return (132, l4.sport, l4.dport)

        # ICMP (IPv4): use Echo ID if present; else type/code packed
        if ICMP in pkt:
            ic = pkt[ICMP]
            sport = getattr(ic, "id", ((ic.type & 0xFF) << 8) | (ic.code & 0xFF))
            return (1, sport, 0)

        # ICMPv6: check echo req/rep first; else type/code packed
        if IPv6 in pkt:
            if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
                ic6 = (pkt.getlayer(ICMPv6EchoRequest) or pkt.getlayer(ICMPv6EchoReply))
                sport = getattr(ic6, "id", 0)
                return (58, sport, 0)
            if pkt.haslayer(ICMPv6Unknown):
                ic6 = pkt[ICMPv6Unknown]
                sport = ((ic6.type & 0xFF) << 8) | (ic6.code & 0xFF)
                return (58, sport, 0)

        # Fallback: unknown L4 (fragments, non-L4). Ports = 0.
        # Protocol comes from IP header if available.
        if IP in pkt:   
            return (pkt[IP].proto, 0, 0)
        if IPv6 in pkt: 
            return (pkt[IPv6].nh,  0, 0)
        
        raise ValueError("Not an IP packet")        

    def five_tuple_extract(self, pkt, bidir=False):
        """Return (src, dst, proto, sport, dport). src/dst are strings."""

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            raise ValueError("Not an IP packet")

        proto, sport, dport = self.get_l4_info(pkt)

        if bidir:
            # Canonicalize so A→B and B→A produce the same key
            s = ip_address(src).packed
            d = ip_address(dst).packed
            if (s, sport, d, dport) > (d, dport, s, sport):
                src, dst, sport, dport = dst, src, dport, sport

        return src, dst, proto, sport, dport
    
    #convert 5-tuple struct to bytes for hashing 
    def five_tuple_key_bytes(self,pkt, bidirectional=False):
        src, dst, proto, sport, dport = self.five_tuple_extract(pkt, bidirectional)
        return (ip_address(src).packed +
                ip_address(dst).packed +
                bytes([proto & 0xFF]) +
                sport.to_bytes(2, "big", signed=False) +
                dport.to_bytes(2, "big", signed=False))        
    
    def toeplitz_rss_hash(self, data: bytes) -> int:
        """32-bit Toeplitz RSS hash (MSB-first), matching rte_softrss_be()."""
        # helper to read one key bit (MSB-first within each byte)
        def kbit(pos: int) -> int:
            byte = self.default_rss_key[pos // 8]
            return (byte >> (7 - (pos % 8))) & 1

        # initial 32-bit window = key bits [0..31]
        window = 0
        for i in range(32):
            window = (window << 1) | kbit(i)
        window &= 0xFFFFFFFF

        h = 0
        key_pos = 32  # next key bit to feed when we shift the window

        for b in data:
            for bit in range(8):
                # consume data bits MSB-first
                if (b >> (7 - bit)) & 1:
                    h ^= window
                # advance window by one key bit
                nextb = kbit(key_pos)
                key_pos += 1
                window = ((window << 1) & 0xFFFFFFFF) | nextb

        return h & 0xFFFFFFFF
    

    def five_tuple_hash(self, pkt, bidirectional=False, algo="rss"):
        """Return an int hash (32/64/128 bits) of the 5-tuple."""
        b = self.five_tuple_key_bytes(pkt, bidirectional)

        if algo =="rss":
            return self.toeplitz_rss_hash(b)
        else:
            return zlib.crc32(b) & 0xFFFFFFFF
    
    #parse a sigle pcap file into separate per core pcaps by flow 
    def parse_pcap(self,pcap_file): 
        from scapy.utils import PcapReader
        non_ip = 0
        #initial read of pcaps and loading of flow table
        pkts = rdpcap(pcap_file)  # loads entire file into memory as Packet objects
        for pkt in pkts:
            try:
                key = self.five_tuple_extract(pkt, bidir=False)
            except ValueError:
                non_ip = non_ip + 1
                continue 
                
            #init flow table with all out entries set to 0 for now
            self.flowtable.add_entry(key) 
        start_pkt_time = pkts[0].time 
        end_pkt_time   = pkts[-1].time

        print("pcap read finished, %d unique flows identified, %d packets dropped for not IP\n" % (self.flowtable.entries, non_ip)) 
        print("pcap_runtime: " + str(end_pkt_time-start_pkt_time))
        return True

    def modify_actiontable(self,kind,moddict):

        for key in self.flowtable.flowtable: 
            for layers in moddict: 
                if layers == "l2_mods":
                    continue 

                elif layers == "l3_mods":
                    for l3_mods in moddict[layers]:
                        #enable src ip replacement if match
                        if l3_mods["tgt_ipv4_addr"] == self.flowtable.flowtable[key]["action_struct"]["src_ip"]:
                            self.flowtable.flowtable[key]["action_struct"]["kind"] = kind
                            self.flowtable.flowtable[key]["action_struct"]["a_src_ip"] = l3_mods["repl_ipv4_addr"]

                        if l3_mods["tgt_ipv4_addr"] == self.flowtable.flowtable[key]["action_struct"]["dst_ip"]:
                            self.flowtable.flowtable[key]["action_struct"]["kind"] = kind
                            self.flowtable.flowtable[key]["action_struct"]["a_dst_ip"] = l3_mods["repl_ipv4_addr"]
                    
                elif layers == "l4_mods":   
                    continue

        return self.flowtable.flowtable

    def export_actiontable(self, filename):
        with open(filename, "w") as f:
            json.dump(self.flowtable.flowtable, f)        


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample argparse program")
    parser.add_argument("-i", "--infile",type=str, default="pcaps/test64.pcap", help="Input Pcapfile to parse")
    args = parser.parse_args()

    pparse = PReplayPcapParser()
    pparse.parse_pcap(args.infile)

    moddict = {"l2_mods" : {},
               "l3_mods" : [{"tgt_ipv4_addr"  : "192.168.1.201",
                            "repl_ipv4_addr" : "172.0.0.0"}],
               "l4_mods" : {}}


    print(pparse.flowtable.flowtable)
    pparse.modify_actiontable(7,moddict)
    print(pparse.flowtable.flowtable)

    pparse.export_actiontable("actions.json")
