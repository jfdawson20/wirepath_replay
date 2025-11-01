'''
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: PacketSmith_Client.py
Description: Simple JSON RPC client for connecting to PacketSmith_Server in RPC mode. I expect the end user to spin their own connection
to the RPC interface depending on their use case. 

'''

import argparse
import json
import socket
import sys

def rpc_call(method, host, port, params=None,  req_id=1):
    msg = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or [],
        "id": req_id,
    }

    print(msg)

    with socket.create_connection((host, port)) as sock:
        sock.sendall((json.dumps(msg) + "\n").encode())
        data = sock.recv(4096).decode().strip()
        response = json.loads(data)
        return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample argparse program")
    parser.add_argument("-c", "--command",type=str, default="server_alive", help="Command to query/execute, see list operation")
    parser.add_argument("-a", "--args",type=str, default="", help="csv list of command arguments (see api documentation)")
    parser.add_argument("-p", "--port",type=int, default=5000, help="RPC Server Port")
    parser.add_argument("-i", "--hostip",type=str, default="localhost", help="RPC Server PortPort Address")

    #parse args
    args = parser.parse_args()

    #handle command
    ret = rpc_call(args.command, args.hostip, args.port, args.args.split(","))
    print(ret)
