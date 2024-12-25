import socket

import psutil
import ipaddress

import scapy.all as scapy
from scapy import all as scapy

from colorama import init, Fore

init()
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
RESET = Fore.RESET


def get_local_network():
    """Automatically retrieves the local network range based on the active interface"""
    interfaces = psutil.net_if_addrs()
    for iface_name, iface_info in interfaces.items():
        for addr in iface_info:
            if addr.family == 2:  # IPv4
                ip = addr.address
                netmask = addr.netmask
                if ip != "127.0.0.1":  # Skip localhost
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    raise ValueError("No active network interface found")


def scan(ip_range):
    """Scans the network in the given IP range and returns a list of devices"""
    print(f"[INFO] Scanning network: {ip_range}")
    request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / request
    answered = scapy.srp(packet, timeout=5, verbose=False)[0]

    devices = []
    for element in answered:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    result = s.getsockname()[0]
    s.close()
    return result


def get_mac(ip):
    """Returns the MAC address for a given IP"""
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / request
    answer = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answer[0][1].hwsrc
