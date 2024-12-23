import pyshark
import threading

from scapy.all import *
from scapy.layers.http import HTTPRequest

from utils import thread_with_trace

from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET


def process_packet(local_packet, printing_queue):
    # print(local_packet)
    if local_packet.haslayer(HTTPRequest):
        url = local_packet[HTTPRequest].Host.decode() + local_packet[HTTPRequest].Path.decode()
        ip = local_packet[IP].src
        method = local_packet[HTTPRequest].Method.decode()
        printing_queue.put(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if local_packet.haslayer(Raw) and method == "POST":
            printing_queue.put(f"\n{RED}[*] Some useful Raw data: {local_packet[Raw].load}{RESET}")


def sniffer_loop_scapy(interface_to_capture_packets, printing_queue, verbosity):
    printing_queue.put(f"{GREEN}[+] Starting sniffer{RESET}")
    sniff(iface=interface_to_capture_packets, prn=lambda x:process_packet(x,printing_queue), store=False)
    # sniff(prn=process_packet, filter="port 80", store=False)


def start_sniffer_thread(interface_to_capture_packets,printing_queue, verbosity=0, ):
    sniffer_thread = thread_with_trace(target=sniffer_loop_scapy, args=(interface_to_capture_packets,printing_queue, verbosity))
    sniffer_thread.start()
    return sniffer_thread



def return_password_from_packet():
    pass


# if __name__ == "__main__":
    # sniffer_loop_scapy("wlan0", 1)
    #for testing purposes
    # sniffer_loop("wlan0",1)
    #start_sniffer_thread("wlan0",1)