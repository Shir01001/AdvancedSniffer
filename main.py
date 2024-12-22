import argparse
import sys

from pycparser.c_ast import While
from queue import Queue

from arp_poisoning import start_arp_poisoning
from http_server import start_http_server_thread
from packet_analysis import start_sniffer_thread

from threading import Lock, Thread


def printer(queue):
    while True:
        message = queue.get()
        print(message +'\n#>')

def initialize_program(interface_pc, mac_address, ip_address, verbosity, local_printing_queue):
    original_thread_list = []
    original_printer_thread = Thread(target=printer, args=(local_printing_queue,), daemon=True,name="Printer")
    printer_thread.start()

    sniffer_thread = start_sniffer_thread(interface_pc,local_printing_queue, verbosity)
    http_server_thread = start_http_server_thread(local_printing_queue)
    # start_arp_poisoning(mac_address)

    original_thread_list.append(http_server_thread)
    original_thread_list.append(sniffer_thread)

    return original_thread_list,original_printer_thread



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default="wlan0")
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity', default=0)
    args = parser.parse_args()

    printing_queue = Queue()

    thread_list, printer_thread = initialize_program(args.interface, args.mac_address, args.address, args.verbosity, printing_queue)
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
                printer_thread.join()
                print("Everything stopped")
                break
            case _:
                print("Not correct command")
