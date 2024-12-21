import pyshark
import threading

def sniffer_loop(interface_to_capture_packets,printing_queue, verbosity):
    if verbosity:
        printing_queue.put("[+] Sniffer started")
    capture = pyshark.LiveCapture(interface=interface_to_capture_packets)
    for packet in capture.sniff_continuously():
        if 'HTTP' in packet or 'HTTPS' in packet and 'POST' in packet:
        #packet.http.request_method == 'POST':
            print(packet)
        #print('Just arrived:', packet)


def start_sniffer_thread(interface_to_capture_packets,printing_queue, verbosity=0, ):
    sniffer_thread = threading.Thread(target=sniffer_loop, args=(interface_to_capture_packets,printing_queue, verbosity))
    sniffer_thread.start()
    return sniffer_thread



def return_password_from_packet():
    pass


if __name__ == "__main__":
    #for testing purposes
    sniffer_loop("wlan0",1)
    #start_sniffer_thread("wlan0",1)