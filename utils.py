import time
from subprocess import run, DEVNULL
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


def run_configuration_commands(router_ip):
    commands = [
        'iptables -F',
        'iptables --policy FORWARD ACCEPT',
        'sysctl -w net.ipv4.ip_forward=1'
    ]

    print(f"{GREEN}[+] Configuring machine as a router{RESET}")
    for command_to_run in commands:
        command = run(command_to_run.split(), stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)
        if command.returncode != 0:
            print(f"{RED}[-] Error in executing: {command_to_run}{RESET}")
            sys.exit(1)
    # Popen(f"/bin/bash -e mitmdump --listen-host {get_local_ip()} --listen-port 8080 --flow-detail 4 '~bq pass'".split(), creationflags=CREATE_NEW_CONSOLE)


def run_restoring_commands():
    commands = [
        'sysctl -w net.ipv4.ip_forward=0'
        'iptables -F'
    ]

    print(f"{GREEN}[+] Restoring machine configuration{RESET}")
    for command_to_run in commands:
        command = run(command_to_run.split(), stdout=DEVNULL, stderr=DEVNULL)
        if command.returncode != 0:
            print(f"{RED}[-] Error in executing: {command_to_run}{RESET}")
            sys.exit(1)

if __name__ == "__main__":
    print(get_local_ip())


def start_printer_thread(local_printing_queue):
    cancel_token = threading.Event()
    printer_thread = threading.Thread(target=printer, args=(local_printing_queue, cancel_token), daemon=True,
                                      name="Printer")
    printer_thread.start()
    return cancel_token


tkinter_text_for_printer = None

def set_text_for_printer(text_widget):
    global tkinter_text_for_printer
    tkinter_text_for_printer = text_widget

def printer(queue,cancel_token):
    print(f"{GREEN}[+] Printing thread started{RESET}")
    while not cancel_token.is_set():
        message = queue.get()

        if tkinter_text_for_printer is not None:
            tkinter_text_for_printer.insert("1.0", message[6:-5]+'\n')

        if message[:3] == "[+]" or message[:3] == "[-]":
            print('\n' + str(message) + '\n#>', end='')
        else:
            print(message)
