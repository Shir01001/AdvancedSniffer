import pyshark


def sniffer_loop(interface_to_capture_packets):
    capture = pyshark.LiveCapture(interface="enp3s0")
    for packet in capture.sniff_continuously():
        if 'HTTP' in packet and hasattr(packet.http, 'request_method') and packet.http.request_method == 'POST':
            print(packet)
        # print('Just arrived:', packet)


def start_sniffer(interface_to_capture_packets, mac_address="", ip_address="", verbosity=0):
    sniffer_loop(interface_to_capture_packets)


def return_password_from_packet():
    pass


if __name__ == "__main__":
    sniffer_loop("enp3s0")
