import argparse
import os
import sys
import time

from queue import Queue

from arp_poisoning import start_arp_poisoning
from http_server import start_http_server_thread
from packet_analysis import start_sniffer_thread

from colorama import init, Fore

from input_data import get_targets_to_attack
from utils import thread_with_trace, run_configuration_commands

init()
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def printer(queue):
    print(f"{GREEN}[+] Printing thread started{RESET}")
    while True:
        message = queue.get()
        if message[:3] == "[*]":
            print(message +'\n#>')
        else:
            print(message)

def initialize_program(interface_pc, mac_address, verbosity, local_printing_queue):
    original_thread_list = []

    run_configuration_commands()

    original_printer_thread = thread_with_trace(target=printer, args=(local_printing_queue,), daemon=True,name="Printer")
    original_printer_thread.start()

    targets = get_targets_to_attack()

    sniffer_thread_token = start_sniffer_thread(interface_pc,local_printing_queue, targets, verbosity)
    http_server_thread = start_http_server_thread(local_printing_queue,verbosity)
    start_arp_poisoning(mac_address)

    original_thread_list.append(http_server_thread)
    original_thread_list.append(sniffer_thread_token)

    return original_thread_list,original_printer_thread



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default="wlan0")
    parser.add_argument('-m', '--mac_address')
    #parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity', default=0)
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[-] Run again with sudo privileges")
        exit(1)

    printing_queue = Queue()

    thread_list, printer_thread = initialize_program(args.interface, args.mac_address, args.verbosity, printing_queue)
    time.sleep(1)
    while True:
        command = input("#>")
        match command:
            case "help":
                print("TBD")
            case "stop":
                for thread in thread_list:
                    thread.kill()
                    thread.join()

            case "exit":
                for thread in thread_list:
                    thread.kill()
                    thread.join()
                printer_thread.kill()
                printer_thread.join()
                print("Everything stopped")
                break
            case _:
                printing_queue.put(f"{RED}[-]Not correct command{RESET}")
