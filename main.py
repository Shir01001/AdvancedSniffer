import argparse
import pyshark
import threading
import sys
import time
import trace

from packet_analysis import start_sniffer
from arp_poisoning import start_arp_poisoning
from http_server import http_server_start


class thread_with_trace(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False

  def start(self):
    self.__run_backup = self.run
    self.run = self.__run
    threading.Thread.start(self)

  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup

  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None

  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace

  def kill(self):
    self.killed = True


def http_server_loop():
    http_server_thread = thread_with_trace(target=http_server_start)
    http_server_thread.start()
    return http_server_thread

def dns_poisoning_loop():
    pass

def initialize_program(interface_pc, mac_address, ip_address, verbosity):

    thread_list = []
    http_server_thread = http_server_loop()
    start_arp_poisoning(mac_address)
    #start_sniffer(interface_pc, mac_address, ip_address, verbosity)
    thread_list.append(http_server_thread)
    #thread_list.append(arp_poisoning_thread)
    return thread_list



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default="wlan0")
    parser.add_argument('-m', '--mac_address')
    parser.add_argument('-a', "--address")
    parser.add_argument('-v', '--verbosity', default=0)
    args = parser.parse_args()

    thread_list = initialize_program(args.interface, args.mac_address, args.address, args.verbosity)
    while True:
        command = input("#>")
        match command:
            case "stop":
                for thread in thread_list:
                    thread.kill()
                    thread.join()
            case "exit":
                break
            case _:
                print("Not correct command")
