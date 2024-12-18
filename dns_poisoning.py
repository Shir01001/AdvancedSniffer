import os

def start_dns_poisoning():
    pass

def add_routing_rule():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

def remove_routing_rule():
    os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")