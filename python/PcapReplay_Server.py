'''
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: PcapReplay_Server.py
Description: entry point for python server front end to manage Pcap Replay dataplane. 
Handles creating Pcap Replay object and launching CLI and RPC services.

'''

import json
import socketserver
import sys 
import argparse
import time

from PcapReplay import PcapReplay
from PcapReplay_Cli import PcapReplayCli


class RPCHandler(socketserver.StreamRequestHandler):
    rpc_methods = {}

    def handle(self):
        for line in self.rfile:
            try:
                request = json.loads(line.decode().strip())
                method = request.get("method")
                params = request.get("params", [])
                req_id = request.get("id")

                if method in self.rpc_methods:
                    try:
                        # Call with positional or keyword args
                        if isinstance(params, dict):
                            result = self.rpc_methods[method](**params)
                        else:
                            result = self.rpc_methods[method](params)

                        response = {"jsonrpc": "2.0", "result": result, "id": req_id}
                    except Exception as e:
                        response = {"jsonrpc": "2.0",
                                    "error": {"code": -32000, "message": str(e)},
                                    "id": req_id}
                else:
                    response = {"jsonrpc": "2.0",
                                "error": {"code": -32601,
                                          "message": f"Method not found: {method}"},
                                "id": req_id}
            except Exception as e:
                response = {"jsonrpc": "2.0",
                            "error": {"code": -32700, "message": f"Parse error: {e}"},
                            "id": None}

            self.wfile.write((json.dumps(response) + "\n").encode())

    def is_alive(self,args=[]):
        return True

class ThreadedRPCServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample argparse program")
    parser.add_argument("-c", "--config",type=str, default="configs/default.json", help="Path to the JSON config file")
    parser.add_argument("-m", "--mode",type=str, default="cli", help="Launch mode - cli or rpcserver")
    parser.add_argument("-p", "--port",type=int, default=5000, help="RPC Server Port")
    parser.add_argument("-i", "--hostip",type=str, default="localhost", help="RPC Server PortPort Address")

    args = parser.parse_args()

    #load config 
    try:
        with open(args.config, "r") as f: 
            sys_config = json.load(f)

    except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
        print(f"Error while loading config '{args.config}': {e}")
        sys.exit(1)        

    #create Pcap Replay object
    preplay = PcapReplay(args.config,sys_config)

    if args.mode == "cli":
        #create CLI interface 
        preplaycli = PcapReplayCli(preplay)
        preplaycli.climain()
    
    elif args.mode == "rpcserver":
        RPCHandler.rpc_methods["server_alive"] = RPCHandler.is_alive
        for commands in preplay.commands:
            RPCHandler.rpc_methods[commands["command"]] = commands["func"]

        with ThreadedRPCServer((args.hostip, args.port), RPCHandler) as server:
            print(f"JSON-RPC server listening on {args.hostip}:{args.port}")
            server.serve_forever()

    else: 
        print("invalid mode: " + args.mode)