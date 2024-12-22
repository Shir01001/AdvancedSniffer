import pyshark
import threading

from scapy.all import *
from scapy.layers.http import HTTPRequest

from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET



def sniffer_loop(interface_to_capture_packets,printing_queue, verbosity):
    if verbosity:
        printing_queue.put("[+] Sniffer started")
    capture = pyshark.LiveCapture(interface=interface_to_capture_packets)
    for packet in capture.sniff_continuously():
        if 'HTTP' in packet or 'HTTPS' in packet and 'POST' in packet:
        #packet.http.request_method == 'POST':
            print(packet)
        #print('Just arrived:', packet)


def http_packet_filter(packet):
    # if packet.haslayer(TCP) and packet.haslayer(Raw):
    #     payload = packet[Raw].load
    #     Check if the payload contains an HTTP request (e.g., starts with "GET", "POST", etc.)
        # if payload.startswith(b"GET") or payload.startswith(b"POST") or \
        #         payload.startswith(b"PUT") or payload.startswith(b"DELETE") or \
        #         payload.startswith(b"HEAD") or payload.startswith(b"OPTIONS"):
        #     return True
    return True

def process_packet(local_packet):
    print(local_packet)
    if local_packet.haslayer(HTTPRequest):
        url = local_packet[HTTPRequest].Host.decode() + local_packet[HTTPRequest].Path.Decode()
        ip = local_packet[IP].src
        method = local_packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if 1 and local_packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {local_packet[Raw].load}{RESET}")


def sniffer_loop_scapy(interface_to_capture_packets, verbosity):
    print("[+] Starting")
    # sniff(iface=interface_to_capture_packets, prn=process_packet, filter="port 80", store=False)
    sniff(prn=process_packet, filter="port 80", store=False)


def start_sniffer_thread(interface_to_capture_packets,printing_queue, verbosity=0, ):
    sniffer_thread = threading.Thread(target=sniffer_loop, args=(interface_to_capture_packets,printing_queue, verbosity))
    sniffer_thread.start()
    return sniffer_thread



def return_password_from_packet():
    pass


if __name__ == "__main__":
    sniffer_loop_scapy("wlan0", 1)
    #for testing purposes
    # sniffer_loop("wlan0",1)
    #start_sniffer_thread("wlan0",1)