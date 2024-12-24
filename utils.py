import subprocess
import sys
import threading

from colorama import init, Fore

from networking_functions import get_local_ip

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

class thread_with_trace(threading.Thread):
    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        self.__run_backup = self.run
        self.run = self.__run
        threading.Thread.start(self)

    def __run(self):
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, event, arg):
        if event == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, event, arg):
        if self.killed:
            if event == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True


def run_configuration_commands():
    commands = [
        'iptables -F',
        'iptables --policy FORWARD ACCEPT',
        'sysctl -w net.ipv4.ip_forward=1',
        # 'xterm -e mitmdump'
    ]

    print("[+] Configuring machine as a router")
    for command_to_run in commands:
        command = subprocess.run(command_to_run.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if command.returncode != 0:
            print(f"{RED}[-] Error in executing: {command_to_run}{RESET}")
            sys.exit(1)


def run_restoring_commands():
    commands = [
        'sysctl -w net.ipv4.ip_forward=0'
        'iptables -F'
    ]

    print("[+] Restoring machine configuration")
    for command_to_run in commands:
        command = subprocess.run(command_to_run.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if command.returncode != 0:
            print(f"{RED}[-] Error in executing: {command_to_run}{RESET}")
            sys.exit(1)

if __name__ == "__main__":
    print(get_local_ip())
