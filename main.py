import argparse
import pyshark

from arp_poisoning import arp_poisoning_loop


def sniffer_loop():
    capture = pyshark.LiveCapture(interface='eth0')
    capture.sniff(timeout=50)



def start_sniffer(interface_to_capture_packets, mac_address="", ip_address="", verbosity=0):
    arp_poisoning_loop()
    sniffer_loop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface')
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity')
    args = parser.parse_args()

    start_sniffer(args.interface, args.mac_address, args.address, args.verbosity)

    print("something")
