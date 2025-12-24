#!/usr/bin/env python3
"""
control_client.py - Python client for the WPR control server.

Protocol:
  - TCP to (host, port)
  - Send: {"cmd": "name", "args": {...}}\n
  - Receive: single JSON object per line

Requires:
  - Python 3.7+
"""

import json
import socket
from typing import Any, Dict, Optional
import types
import argparse 

class WpsControlError(Exception):
    """Raised when the control server returns an error or the connection fails."""
    pass


class WpsControlClient:
    def __init__(
        self,
        hostip: str = "127.0.0.1",
        port: int = 9000,
        timeout: float = 2.0,
        auto_bind_commands: bool = True,
    ) -> None:
        """
        :param host: Control server address (default: loopback)
        :param port: Control server TCP port (must match your DPDK app)
        :param timeout: Socket timeout in seconds
        :param auto_bind_commands: If True, query 'help' and add methods dynamically
        """
        self.host = hostip
        self.port = port
        self.timeout = timeout

        if auto_bind_commands:
            try:
                self._bind_remote_commands()
            except Exception as e:
                # Don’t explode in __init__, you can still use call()
                print(f"[WPR ctl] Warning: failed to bind remote commands: {e!r}")

    # -------------------------------------------------------------------------
    # Low-level transport
    # -------------------------------------------------------------------------
    def _send_recv_line(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Open a short-lived TCP connection, send one JSON command, read one line.
        """
        data = json.dumps(payload) + "\n"

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            # Use file-like wrapper for line-based reading
            f = sock.makefile("rwb", buffering=0)
            f.write(data.encode("utf-8"))
            # Single \n-terminated JSON reply
            line = f.readline()
            if not line:
                raise WpsControlError("Empty response from control server")

        try:
            return json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise WpsControlError(f"Invalid JSON response: {e}: {line!r}")

    # -------------------------------------------------------------------------
    # Generic command interface
    # -------------------------------------------------------------------------
    def call(self, cmd: str, args = None, raise_on_error: bool = True,
    ) -> Dict[str, Any]:
        """
        Send a generic command to the control server.

        :param cmd: Command name (e.g. "ping", "port_stats")
        :param args: Optional args dict (will be encoded as "args": {...})
        :param raise_on_error: If True, raise WpsControlError on {"error": ...}
        :return: Parsed JSON reply as dict
        """
        payload = {
            "cmd": cmd,
            "args": args or {},
        }
        reply = self._send_recv_line(payload)

        if raise_on_error and isinstance(reply, dict) and "error" in reply:
            raise WpsControlError(f"Server error for cmd='{cmd}': {reply['error']}")

        return reply

    def help(self) -> Dict[str, Any]:
        """
        Fetch and return the raw help document from the server.
        """
        return self.call("help")

    # -------------------------------------------------------------------------
    # Dynamic command binding
    # -------------------------------------------------------------------------
    def _bind_remote_commands(self) -> None:
        """
        Call 'help' on the server and dynamically add a method for each command.
        Each command becomes a method: client.<name>(**args_dict)
        """
        doc = self.help()
        commands = doc.get("commands", [])
        if not isinstance(commands, list):
            return

        for cmd_def in commands:
            name = cmd_def.get("name")
            desc = cmd_def.get("description", "")
            if not isinstance(name, str):
                continue

            # Don't overwrite existing attributes (e.g., .call, .help)
            if hasattr(self, name):
                continue

            method = self._make_cmd_method(name)
            method.__name__ = name
            method.__doc__ = f"Auto-generated method for control cmd='{name}'.\n\n{desc}"

            setattr(self, name, types.MethodType(method, self))

    @staticmethod
    def _make_cmd_method(cmd_name: str):
        """
        Build a method that calls `self.call(cmd_name, args=kwargs)`.
        """

        def _method(self: "WpsControlClient", **kwargs: Any) -> Dict[str, Any]:
            return self.call(cmd_name, args=kwargs)

        return _method


# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wirepath Switch Control Client")
    parser.add_argument("-p", "--port",type=int, default=9000, help="RPC Server Port")
    parser.add_argument("-i", "--hostip",type=str, default="localhost", help="RPC Server PortPort Address")
    parser.add_argument("-c", "--command",type=str, default="help", help="Return help document from server")
    parser.add_argument("-a", "--args",type=str, default="", help="Return help document from server")   

    cli_args = parser.parse_args()
    # Adjust port to match thread_args->controller_port in your DPDK app
    client = WpsControlClient(port=cli_args.port, hostip=cli_args.hostip)

    # Parse args JSON (if provided)
    if cli_args.args:
        try:
            cmd_args = json.loads(cli_args.args)
            if not isinstance(cmd_args, dict):
                raise ValueError("Top-level -a/--args JSON must be an object")
        except Exception as e:
            raise SystemExit(f"Failed to parse -a/--args as JSON: {e}")
    else:
        cmd_args = {}

    print(cmd_args)
    # 1) Prefer auto-bound method if available (client.<cmd_name>)
    if hasattr(client, cli_args.command):
        method = getattr(client, cli_args.command)
        if callable(method):
            result = method(**cmd_args)
        else:
            raise SystemExit(f"Attribute '{cli_args.command}' exists but is not callable")
    else:
        # 2) Fall back to generic call() if not auto-bound
        result = client.call(cli_args.command, args=cmd_args)

    # Pretty-print the result
    print(json.dumps(result, indent=2))

    
