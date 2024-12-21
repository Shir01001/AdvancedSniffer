import os
import logging as log
import platform

from scapy.all import *
# from scapy.all import IP, DNSRR,DNSQR,UDP,DNS




def add_routing_rule():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

def remove_routing_rule():
    os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")


def start_dns_poisoning():
    pass

def dns_poisoning_loop():
    pass