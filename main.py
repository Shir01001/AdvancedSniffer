import argparse
import pyshark

from packet_analysis import start_sniffer
from arp_poisoning import start_arp_poisoning
from http_server import http_server_start


def initialize_program(interface_pc="wlan0"):
    http_server_start()
    # start_arp_poisoning()
    start_sniffer(interface_pc, args.mac_address, args.address, args.verbosity)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface')
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity')
    args = parser.parse_args()

    initialize_program(args.interface)
    while True:
        command = input("#>")
        match command:
            case "exit":
                break
            case _:
                print("Not correct command")
