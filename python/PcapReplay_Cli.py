'''
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: PacketSmith_Cli.py
Description: simple prompt_toolkit based CLI wrapper for interacting with PacketSmith application 

'''


from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import clear 
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style
import shlex


class PcapReplayCli():
    def __init__(self, psmith): 
        #setup basic properties of cli
        #packetsmith object
        self.psmith = psmith

        self.commands = psmith.get_supported_commands()
        
        # Autocompleters
        self.cli_completer = WordCompleter(self.commands, ignore_case=True)

        # History
        self.history = InMemoryHistory()

        # Style (colors)
        self.style = Style.from_dict({"prompt": "#00ff00 bold",})

    #handle command string parsing and execution
    def handle_command(self,line: str):
        line = line.strip()

        try:
            tokens = shlex.split(line)
        except ValueError as e:
            print(f"Parse error: {e}")
            return True
        
        if tokens == []:
            return True

        cmd, *cliargs = tokens

        cmd = cmd.lower()        
        print(cmd)
        if cmd == "help": 
            for i in range(len(self.commands)): 
                print("%s - %s" % ((self.psmith.commands[i]["command"]),self.psmith.commands[i]["help"]))

        elif cmd == "clear":
            clear()

        elif cmd in self.commands: 
            for i in range(len(self.psmith.commands)):
                if cmd == self.psmith.commands[i]["command"]:
                    if len(cliargs) > 0:
                        ret = self.psmith.commands[i]["func"](args=cliargs)
                    else: 
                        ret = self.psmith.commands[i]["func"]()
                    print(ret)

        elif cmd == "exit":
            print("Exiting...")
            return False 
        
        elif cmd not in self.commands: 
            print("unknown command")

        return True


    def climain(self):
        self.session = PromptSession(history=self.history)

        while True:
            try:
                cmd = self.session.prompt("PacketSmith> ",completer=self.cli_completer,style=self.style,)
                if not self.handle_command(cmd):
                    break
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                break

if __name__ == "__main__":
    cli = PcapReplayCli()
    cli.climain()
