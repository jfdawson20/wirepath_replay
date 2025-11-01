'''
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: PacketSmith.py
Description: Main API for interfacing with PacketSmith DPDK Dataplane. Contains functions for 
configuring and launching the DPDK datapath and helper functions to issue command and process responses 
from the dataplane socket interface. 

'''

import socket
import json
import sys
import subprocess
import time
import atexit
import os
from scapy.utils import PcapReader
from prettytable import PrettyTable
from pathlib import Path

from PcapReplay_PcapParser import PReplayPcapParser

#main class for interfacing with the DPDK traffic gen subsystem 
class PcapReplay():
    def __init__(self, cfgfile, system_config, hostip="127.0.0.1", port=9000, max_payload=65536):
        self.config_file    = cfgfile
        self.sys_config     = system_config
        self.tx_cores       = system_config["core_config"]["tx_cores"]
        self.hostip         = hostip 
        self.port           = port 
        self.max_payload    = max_payload
        self.dpdk_proc      = None
        self.pcap_parser    = PReplayPcapParser()
        #table for easy converting of pagesizes in config to kB
        self.pagesizes = {"1G" : 1048576}

        #struct to map commands to functions / help strings / etc
        self.commands = [
            {"command" : "list_commands",           "help" : "List supported commands",                         "func" : self.get_supported_commands},
            {"command" : "get_help",                "help" : "Print help info for specified command",           "func" : self.get_help},
            {"command" : "load_app",                "help" : "configure and load dataplane app",                "func" : self.load_dpdk},
            {"command" : "ping_app",                "help" : "Ping DPDK app, sign of life",                     "func" : self.ping_host},
            {"command" : "app_status",              "help" : "Get DPDK dataplane state / status",               "func" : self.get_dpdk_status},
            {"command" : "port_stats",              "help" : "Get Portstats",                                   "func" : self.get_portstats},
            {"command" : "mem_stats",               "help" : "Get memory stats",                                "func" : self.get_memstats},
            {"command" : "load_pcap",               "help" : "load pcap file single",                           "func" : self.load_pcap_file_single},
            {"command" : "list_pcaps",              "help" : "list pcaps loaded into datapath",                 "func" : self.list_pcap_files},
            {"command" : "list_coremap",            "help" : "Get Tx to Buff core mapping",                     "func" : self.get_coremap},
            {"command" : "tx_enable",               "help" : "Enable transmission on all or a single port",     "func" : self.tx_enable},
            {"command" : "tx_disable",              "help" : "Disable transmission on all or a single port",    "func" : self.tx_disable},
            {"command" : "set_tx_rate",             "help" : "Set Transmit Rate (mbps) cmd port vf rate",       "func" : self.set_port_rate},
            {"command" : "en_virt_flows",           "help" : "enable virtual flows per port",                   "func" : self.en_virt_flows},
            {"command" : "pcap_assign_port_all",    "help" : "assign a txcore+port slot a specific pcap",       "func" : self.assign_slot_port_all},
            {"command" : "add_ft_action",           "help" : "add new flowtable action",                        "func" : self.add_flowaction},
            {"command" : "mod_ft_action",           "help" : "modify existing flowtable action",                "func" : self.mod_flowaction},
            {"command" : "del_ft_action",           "help" : "delete existing flowtable action",                "func" : self.del_flowaction},
            {"command" : "load_ft_actions",         "help" : "bulk load actions",                               "func" : self.load_flowactions}
        ]

        self.slot_manager = []

    def print_progress_bar(self,iteration, total, prefix='', suffix='', length=50, fill='█'):
        """
        Print progress bar in place on one line.
        
        Args:
            iteration (int): current iteration (0-based)
            total (int): total iterations
            prefix (str): optional text before bar
            suffix (str): optional text after bar
            length (int): length of bar in characters
            fill (str): character to fill completed portion
        """
        percent = 100 * (iteration / float(total))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent:6.2f}% {suffix}')
        sys.stdout.flush()
        if iteration >= total:
            sys.stdout.write('\n')

    def get_supported_commands(self,args=[]): 
        commands = []
        for c in self.commands: 
            commands.append(c["command"])

        return commands 

    def get_help(self,args=[]):
        for c in self.commands: 
            if c["command"] == args[0]:
                return c["help"]
    
    #check if hugepages are already configured and mounted
    def are_hugepages_configured(self):
        # check if hugetlb field has any entries, should show > 0 if configured 
        ret = subprocess.run(["grep", "Huge", "/proc/meminfo"], capture_output=True, text=True).stdout.split("\n")
        for fields in ret: 
            if "Hugetlb" in fields: 
                total_hugepages = fields.split(":")[1].strip().split("kB")[0]

        if int(total_hugepages) == 0: 
            return False
        
        # check if hugetlbfs is mounted with 1G pages 
        ret = subprocess.run(["grep", "hugetlbfs", "/proc/mounts"], capture_output=True, text=True).stdout.split("\n")
        mounted = False
        for fields in ret: 
            if "pagesize=1024M" in fields: 
                mounted = True 
                
        return mounted 
    
    #configure and mount hugepages based on config
    def configure_hugepages(self):

        if (self.are_hugepages_configured() == True):
            print("already configured hugepages")
            return True 
        
        #create hugepages per config 
        num_pages = self.sys_config["memory_configs"]["num_pages"]
        pagesize  = self.pagesizes[self.sys_config["memory_configs"]["default_hugepage_size"]]
        cmd = "echo %d | sudo tee /sys/kernel/mm/hugepages/hugepages-%dkB/nr_hugepages > /dev/null" % (num_pages,pagesize)
        
        ret = subprocess.run(cmd, shell=True)
        if (ret.returncode != 0 ):
            print("Failed to create %d pages of size %d" % (num_pages,pagesize))
            return (ret.returncode)
        
        #make mountpoint for hugetblfs
        cmd = "sudo mkdir -p /mnt/huge"
        ret = subprocess.run(cmd, shell=True)
        if (ret.returncode != 0 ):
            print("Failed to make /mnt/huge mountpoint")
            return (ret.returncode)    

        #mount hugetblfs
        cmd = "sudo mount -t hugetlbfs nodev /mnt/huge -o pagesize=%s" % self.sys_config["memory_configs"]["default_hugepage_size"]
        ret = subprocess.run(cmd, shell=True)
        if (ret.returncode != 0 ):
            print("Failed to mount hugetlbfs with page size %s" % self.sys_config["memory_configs"]["default_hugepage_size"])
            return (ret.returncode)        
    
        return True
    
    #create requested number of VF's for use with DPDK app
    def create_vfs(self):
        #for each port specificed in the config file 
        for p in self.sys_config["port_configs"]: 
            #check if VF's already created 
            cmd = "cat /sys/bus/pci/devices/%s/sriov_numvfs" % p["pf_devid"]
            ret = subprocess.run(cmd, shell=True, capture_output=True)

            #if VFs already configured for port, continue 
            if (int(ret.stdout) == int(p["numvfs"])):
                print("already created")
                continue 
            
            else: 
                numvfs = p["numvfs"]
                pciid  = p["pf_devid"]
                cmd = "echo %d | sudo tee /sys/bus/pci/devices/%s/sriov_numvfs > /dev/null" % (numvfs,pciid)
                ret = subprocess.run(cmd, shell=True)                
                if (ret.returncode != 0):
                    print("Failed to create %d VFs for Device %s" % (numvfs,pciid))
                    return False 

        return True 

    # configure and launch DPDK dataplane application using settings in config file
    def launch_dataplane(self):
        app         = self.sys_config["dpdk_config"]["appname"]
        path        = self.sys_config["dpdk_config"]["path"] 
        start_core  = self.sys_config["core_config"]["base_lcore_id"] 
        end_core    = self.sys_config["core_config"]["total_lcores"]-1

        cmd = []

        binarypath = "./%s/%s" % (path,app)
        cores      = "%d-%d" % (start_core,end_core)

        cmd.append(binarypath)
        cmd.append("-l")
        cmd.append(cores)
        #append all configured VF interfaces, VF's are the primary transmit port target for this app
        for p in self.sys_config["port_configs"]: 
            for v in p["vf_devids"]:
                cmd.append("-a")
                cmd.append(v)

        cmd.append("--")
        cmd.append("--config")
        cmd.append(self.config_file)

        print(cmd)

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            print(f"Failed to start process: {e}")
            return False
        
        #save proc struct for later
        self.dpdk_proc = proc

        #register terminate with atexit for cleanup 
        atexit.register(self.dpdk_proc.terminate)
        return True

    #poll functiont to wait for application to launch, success if it can connect to DPDK mgmt socket
    def poll_for_app(self, timeout=30):
        start = time.time()
        while True:
            try:
                with socket.create_connection((self.hostip, self.port), timeout=1):
                    print(f"Socket is open on {self.hostip}:{self.port}")
                    print("Connected")
                    break
            except (OSError, ConnectionRefusedError):
                if time.time() - start > timeout:
                    print("Timeout waiting for socket")
                    self.dpdk_proc.terminate()
                    raise SystemExit(1)
                time.sleep(1)  # wait before retry


    #main command function, open/close socket every time to keep state clean if errors happen 
    def execute_command(self,command,raw=""):
        #create and connect to DPDK application 
        try:
            s = socket.socket()
            s.connect((self.hostip, self.port))
        except socket.error as e:
            print("Failed to open connection to DPDK app, is it running? Error - {e}")
            return (-1, "")

        #format and send json command, allow for manual injection of raw strings for testing
        if raw == "":
            msg = json.dumps(command) + "\n"
        else:
            msg = raw

        try:
            s.sendall(msg.encode())
        except (BrokenPipeError, ConnectionResetError, socket.error) as e:
            print("Failed to transmit command. Error - {e}")
            return (-1, "")

        #return result 
        try:
            ret = json.loads(s.recv(self.max_payload).decode("utf-8"))
            s.close()
            return (0,ret)

        except (socket.timeout, socket.error) as e:
            print("Failed to recieve DPDK app response. Error - {e}")
            return (-1, "")

    # accessor functions 
    def load_dpdk(self, args=[]):
        """ Load DPDK Dataplane Application """
        if self.dpdk_proc != None: 
            ret = self.dpdk_proc.poll()
            if ret is None:
                print("DPDK app already running with process id: %d\n" % self.dpdk_proc.pid)
                return True
            
        ret = self.configure_hugepages()
        if (ret == False):
            print("failed to configure hugepages for dpdk app")
            return False

        ret = self.create_vfs()
        if (ret == False):
            print("failed to configure vf's for dpdk use")
            return False
        
        ret = self.launch_dataplane()
        if (ret == False):
            print("failed to launch DPDK binary")
            return False
        
        self.poll_for_app()

        return True

    #check how many ports were configured at launch time
    def check_port_valid(self,portno):
        #check how many ports were actually configured 
        port_count = 0
        for ports in self.sys_config["port_configs"]:
            port_count = port_count + ports["numvfs"]

        if portno > port_count: 
            print("error, port number %d out of range, max port number %d\n" % (portno, port_count))
            return False 
        
        return True 
        
    #basic ping / response test, see if DPDK app is alive 
    def ping_host(self,args=[]): 
        """ Ping DPDK Dataplane for sign of life """
        cmd = {"cmd" : "ping", "args" : {}}
        return (self.execute_command(cmd))
    
    #return DPDK global status struct 
    def get_dpdk_status(self,args=[]):
        """ Get DPDK Dataplane system status state """
        cmd = {"cmd" : "status", "args" : {}}
        return (self.execute_command(cmd))
    
    #set the tx rate limit on a port 
    def set_port_rate(self, args=[]):
        """ Set transmit rate for a specific port ID, port id = -1 is all ports """
        try:
            #check arg length
            if len(args) != 3:
                print("Incorrect arguments: expected pfno:<pfno> vfno:<vfno> rate:<rate in mb/s>")
                return -1

            pf = None
            vf = None
            rate = None 
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "pfno":
                    pf = int(cmd_tokens[1])
                elif cmd_tokens[0] == "vfno":
                    vf = int(cmd_tokens[1])
                elif cmd_tokens[0] == "rate":
                    rate = int(cmd_tokens[1])
            
            if pf == None or vf == None or rate == None: 
                print("Incorrect arguments: expected pf_num:<pfno> vf_num:<vfno> rate:<rate in mb/s>")
                return -1
        except Exception as e: 
                print("Incorrect arguments: expected pf_num:<pfno> vf_num:<vfno> rate:<rate in mb/s>")
                return -1    

        netdev = self.sys_config["port_configs"][pf]["portnetd"]
        cmd = "sudo ip link set dev %s vf %d max_tx_rate %d" % (netdev, vf, rate)
        ret = subprocess.run(cmd, shell=True)                
        if (ret.returncode != 0):
            print("Failed to set rate limit %d on netdev %s port (vf) %d" % (rate,netdev,vf))
            return False         

        return {}

    
    #fetch all configured portstats, returns a json file organized by portid 
    #input "args" comes from CLI tokens, expected format: 
    #args = [portid/all, true/false, filter(optional)]
    def get_portstats(self,args=["all","false"]):
        """ Get Port Stats for all ports """
        cmd = {"cmd" : "port_stats", "args" : {}}
        s, ret_data = self.execute_command(cmd) 

        #filter out zero'd fields if request
        if len(args) >=2 and args[1] == "true": 
            tmp = {}
            for ports in ret_data:
                tmp[ports] = {}
                for stats in ret_data[ports]:
                    if int(ret_data[ports][stats]) != 0: 
                        tmp[ports][stats]=ret_data[ports][stats]
            ret_data = tmp

        #filter by field if requested 
        if len(args) == 3: 
            tmp = {}
            for ports in ret_data:
                tmp[ports] = {}
                for stats in ret_data[ports]:
                    if args[2] in stats: 
                        tmp[ports][stats] = ret_data[ports][stats]
            ret_data = tmp 

        #filter by port if asked
        if args[0] in ret_data:
            ret_data = ret_data[args[0]]

        return ret_data

    def load_pcap_file_single(self,args=[]):
        """ Load a pcap file into memory """
        try:
            #check arg length
            if len(args) != 1:
                print("Incorrect arguments: expected filepath:</path/to/filename.pcap>")
                return -1

            cmd_tokens = args[0].strip().split(":")
            print(cmd_tokens)
            if (len(cmd_tokens) != 2) or (cmd_tokens[0] != "filepath"):
                print("Invalid command: %s, expected filepath:</path/to/filename.pcap>" % args[0])
                return -1 
        except Exception as e: 
            print("Invalid command: %s, expected filepath:</path/to/filename.pcap>" % args[0])
            return -1             
        
        filename = cmd_tokens[1]
    
        #check if valid pcap
        try:
            with PcapReader(filename) as pcap:
                # Try reading just one packet
                next(pcap)
        except Exception as e:
            print("couldn't parse pcap file, invalid format")
            return False        

        #if we are good, send command to load pcap
        cmd = {"cmd" : "load_pcap", "args" : {"filename" : filename}}
        print(cmd)
        ret = self.execute_command(cmd)
        if ret[0] != 0:
            print("failed to load pcap")
            return (ret)
        
        else:
            #create slot manager entry 
            slot_entry = {"slotid":ret[1]["slot"],"pcap_name" : filename, "numpackets" : ret[1]["num_packets"]}
            
            #if slot is already in use, update it
            if ret[1]["slot"] < len(self.slot_manager):
                self.slot_manager[ret[1]["slot"]] = slot_entry
            
            elif ret[1]["slot"] == len(self.slot_manager):
                self.slot_manager.append(slot_entry)

            else:
                print("Error slot ID not expected, greater than slot manager list size")

        return ret
    
    #list pcaps that are already loaded into memory
    def list_pcap_files(self,args=[]):
        """ List Pcap file storage from python server memory """
        slotdict = {"pcap_slots" : []}
        slotdict["pcap_slots"] = self.slot_manager

        return slotdict

    #return dpdk memstats structures
    def get_memstats(self,args=[]):
        """ Get DPDK Dataplane memory stats """
        cmd = {"cmd" : "mem_stats", "args" : {}}
        return (self.execute_command(cmd))

    #get a mapping of which buffer lcores are linked to each tx lcore
    def get_coremap(self, args=[]):
        """ Get tx to buffer core mappings from DPDK  """
        cmd = {"cmd" : "list_coremap", "args" : {}}
        return (self.execute_command(cmd))      

    #set number of virtual channels to use per port, in dynamic expansion mode
    def en_virt_flows(self, args=[]):
        """ Get tx to buffer core mappings from DPDK  """
        try:
            #check arg length
            if len(args) != 2:
                print("Incorrect arguments: expected portno:<portno> vc:<num_virt_channels>")
                return -1

            vc = None
            portno = None
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "portno":
                    portno = int(cmd_tokens[1])
                elif cmd_tokens[0] == "vc":
                    vc = int(cmd_tokens[1])
            
            if portno == None or vc == None: 
                print("Incorrect arguments: expected portno:<portno> vc:<num_virt_channels>")
                return -1
        except Exception as e: 
                print("Incorrect arguments: expected portno:<portno> vc:<num_virt_channels>")
                return -1    



        cmd = {"cmd" : "virt_channels_enabled", "args" : {"portno" : portno, "virt_channels" : vc}}
        return (self.execute_command(cmd))      

    def tx_enable(self, args=[]):
        """ Enable tx on a port, -1 is all ports """
        try:
            #check arg length
            if len(args) != 1:
                print("Incorrect arguments: portno:<portno>")
                return -1

            portno = None
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "portno":
                    portno = int(cmd_tokens[1])

            if portno == None:
                print("Incorrect arguments: portno:<portno>")
                return -1
        except Exception as e: 
                print("Incorrect arguments: portno:<portno>")
                return -1   
            
        if self.check_port_valid(portno) == False: 
            return {}

        cmd = {"cmd" : "tx_enable", "args" : {"portno" : portno}}
        return (self.execute_command(cmd))     

    def tx_disable(self, args=[]):
        """ Disable tx on a port, -1 is all ports """
        try:
            #check arg length
            if len(args) != 1:
                print("Incorrect arguments: portno:<portno>")
                return -1

            portno = None
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "portno":
                    portno = int(cmd_tokens[1])

            if portno == None:
                print("Incorrect arguments: portno:<portno>")
                return -1
        except Exception as e: 
                print("Incorrect arguments: portno:<portno>")
                return -1   

        cmd = {"cmd" : "tx_disable", "args" : {"portno" : portno}}
        return (self.execute_command(cmd))     

    def assign_slot(self, args=[]):
        """ Assign a pre-loaded Pcap entry to a specific port and tx core  """
        slotid = int(args[0])
        portno = int(args[1])
        tx_id  = int(args[2])
        mode  = int(args[3])

        #check slotid   
        if slotid < 0 or slotid > len(self.slot_manager):
            print("invalid slot id %d\n")
            return (-1,{})
        
        #check port number
        if self.check_port_valid(portno) == False: 
            return (-1,{})
        
        #check tx core id
        if tx_id < 0 or tx_id > self.sys_config["core_config"]["tx_cores"]:
            print("invalid core id %d\n")
            return (-1,{})

        cmd = {"cmd" : "slot_assign", "args" : {"pcap_slotid" : slotid, "portno": portno, "coreid": tx_id, "mode" : mode}}
        print(cmd)
        return (self.execute_command(cmd))  

    def assign_slot_port_all(self, args=[]):
        """ Assign a pre-loaded Pcap entry to a specific port and tx core  """
        try:
            #check arg length
            if len(args) != 3:
                print("Incorrect arguments: expected pcap:<pcap name> portno:<portno> mode:<mode>")
                return -1

            pcap_name = None
            portno = None
            mode = None 
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "pcap":
                    pcap_name = cmd_tokens[1]
                elif cmd_tokens[0] == "portno":
                    portno = int(cmd_tokens[1])
                elif cmd_tokens[0] == "mode":
                    mode = int(cmd_tokens[1])
            
            if pcap_name == None or portno == None or mode == None: 
                print("Incorrect arguments: expected pcap:<pcap name> portno:<portno> mode:<mode>")
                return -1
        except Exception as e: 
                print("Incorrect arguments: expected pcap:<pcap name> portno:<portno> mode:<mode>")
                return -1            

        slotid = -1
        #get slot ID 
        for entries in self.slot_manager:
            #find the right slot entries
            if "/" in entries["pcap_name"]:
                if (pcap_name) == entries["pcap_name"].split("/")[1]:
                    slotid = entries["slotid"] 
            else: 
                if (pcap_name) == entries["pcap_name"]:
                    slotid = entries["slotid"]                 

        #check port number
        if self.check_port_valid(portno) == False: 
            return (-1,{})
        
        for i in range(self.tx_cores):
            args = [slotid,portno,i,mode]
            ret = self.assign_slot(args)
          
    def add_flowaction(self, args=[]):
        flowaction = {"kind"   : 3,
                      "src_ip" : "192.168.1.100",
                      "dst_ip" : "192.168.1.1",
                      "src_port" : 12345,
                      "dst_port" : 54321,
                      "proto" : 17,
                      "a_src_mac" : "0:0:0:0:0:0",
                      "a_dst_mac" : "0:0:0:0:0:0",
                      "a_src_ip" : "172.0.0.0",
                      "a_dst_ip" : "168.0.0.0",
                      "a_src_port" : 0,
                      "a_dst_port" : 0}
        
        for a in args:
            fmt = a.strip().split(":")
            if len(fmt) == 2:
                if fmt[0] in flowaction: 
                    flowaction[fmt[0]] = fmt[1]

        cmd = {"cmd" : "add_flowaction", "args" : flowaction}
        return (self.execute_command(cmd))   
    
    def mod_flowaction(self, args=[]):
        flowaction = {"kind"   : 3,
                      "src_ip" : "192.168.1.100",
                      "dst_ip" : "192.168.1.1",
                      "src_port" : 12345,
                      "dst_port" : 54321,
                      "proto" : 17,
                      "a_src_mac" : "-1",
                      "a_dst_mac" : "0:0:0:0:0:0",
                      "a_src_ip" : "155.0.0.0",
                      "a_dst_ip" : "122.0.0.0",
                      "a_src_port" : 500,
                      "a_dst_port" : 0}
        
        for a in args:
            fmt = a.strip().split(":")
            if len(fmt) == 2:
                if fmt[0] in flowaction: 
                    flowaction[fmt[0]] = fmt[1]

        cmd = {"cmd" : "mod_flowaction", "args" : flowaction}
        return (self.execute_command(cmd))   

    def del_flowaction(self, args=[]):
        flowkey = {"src_ip" : "192.168.1.100",
                      "dst_ip" : "192.168.1.1",
                      "src_port" : 12345,
                      "dst_port" : 54321,
                      "proto" : 17}
        
        for a in args:
            fmt = a.strip().split(":")
            if len(fmt) == 2:
                if fmt[0] in flowkey: 
                    flowkey[fmt[0]] = fmt[1]

        cmd = {"cmd" : "del_flowaction", "args" : flowkey}
        return (self.execute_command(cmd))   
    
    def append_flowaction(self, flowaction):
   
        cmd = {"cmd" : "add_flowaction", "args" : flowaction}
        return (self.execute_command(cmd))   
    
    def load_flowactions(self,args=[]):
        try:
            #check arg length
            if len(args) != 1:
                print("Incorrect arguments: expected filename:<flowactions.json>")
                return -1

            filename = None
            for a in args:
                cmd_tokens = a.strip().split(":")
                if cmd_tokens[0] == "filename":
                    filename = cmd_tokens[1]
            
            if filename == None: 
                print("Incorrect arguments: expected file:<flowactions.json>")
                return -1
            
        except Exception as e:            
            print("Incorrect arguments: expected file:<flowactions.json>")
            return -1  
        
        #try to load json file
        try:
            with open(filename, "r") as f: 
                ft_actions = json.load(f)

        except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
            print(f"Error while loading config '{filename}': {e}")
            return {}
        
        i = 0
        for entries in ft_actions:
            ret = self.append_flowaction(ft_actions[entries]["action_struct"])
            self.print_progress_bar(i,len(ft_actions))
            i = i + 1

        print("\n%d Flowtable Actions Loaded\n" % len(ft_actions))