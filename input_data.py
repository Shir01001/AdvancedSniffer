from networking_functions import scan, get_local_network


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


def get_targets_to_attack_and_router(mac_address=-1, ip_address=-1):
    try:
        target_device = None
        network_range = get_local_network()
        devices = scan(network_range)

        if not devices:
            print("[-]No devices found on the network.")
            exit(1)


        if mac_address is None:
            target_device = display_menu(devices)
        else:
            for device in enumerate(devices):
                if device['mac'] == mac_address or device["ip"] == ip_address:
                    target_device = device

        if target_device is None:
            return

        router_ip = input("Enter the router's IP: ")

        return target_device, router_ip
    except Exception as e:
        print(f"[-]Error {e}")