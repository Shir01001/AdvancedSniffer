import pyshark
import threading

from scapy.all import *

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
    print("\n--- HTTP Packet Captured ---")
    # Print basic packet information
    # print(f"Source IP: {packet[IP].src}")
    # print(f"Destination IP: {packet[IP].dst}")
    # print(f"Source Port: {packet[TCP].sport}")
    # print(f"Destination Port: {packet[TCP].dport}")
    # Print HTTP payload
    if local_packet.haslayer(Raw):
        http_payload = local_packet[Raw].load
        try:
            print("HTTP Data:")
            print(http_payload.decode(errors='ignore'))  # Decode HTTP payload
        except UnicodeDecodeError:
            print("Could not decode HTTP payload.")


def sniffer_loop_scapy(interface_to_capture_packets, verbosity):
    sniff(iface=interface_to_capture_packets,filter="tcp port 80", prn=lambda x:x.summary(), store=False)


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