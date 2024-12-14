import pyshark


def sniffer_loop(interface_to_capture_packets):
    capture = pyshark.LiveCapture(interface=interface_to_capture_packets, )
    capture.sniff(timeout=50)


def start_sniffer(interface_to_capture_packets, mac_address="", ip_address="", verbosity=0):
    sniffer_loop(interface_to_capture_packets)


def return_password_from_packet():
    pass
