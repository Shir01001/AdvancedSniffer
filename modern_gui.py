import tkinter as tk
from tkinter import ttk, Label

from pandas.core.dtypes.inference import is_integer

from arp_poisoning import start_arp_poisoning
from dns_poisoning import start_dns_poisoning
from http_server import start_http_server_thread, stop_server
from mitm_proxy import start_mitm_proxy_thread
from packet_analysis import start_sniffer_thread

from utils import set_text_for_printer

tokens_dictionary = {"arp": 0, "sniffer": 0, "dns": 0, "http": 0, "proxy": 0}

interface_pc=None
mac_address=None
targeted_ip=None
router_ip=None
verbosity=None
local_printing_queue=None

def gui_callback(option_for_action, type_of_action, target_ip_entry, router_ip_entry):
    global targeted_ip
    global router_ip

    targeted_ip = target_ip_entry.get()
    router_ip = router_ip_entry.get()

    match option_for_action:
        case "arp":
            if type_of_action and tokens_dictionary["arp"] == 0:
                tokens_dictionary["arp"] = start_arp_poisoning(interface_pc, targeted_ip, router_ip, local_printing_queue, verbosity)
                tokens_dictionary["sniffer"] = start_sniffer_thread(interface_pc, targeted_ip, router_ip, local_printing_queue,verbosity)
            else:
                arp_token = tokens_dictionary["arp"]
                sniffer_token = tokens_dictionary["sniffer"]
                if not is_integer(arp_token) :
                    arp_token.set()
                    sniffer_token.set()
                    tokens_dictionary["arp"] = 0
                    tokens_dictionary["sniffer"] = 0
        case "dns":
            if type_of_action and tokens_dictionary["dns"] == 0:
                tokens_dictionary["dns"] =  start_dns_poisoning(interface_pc, targeted_ip, router_ip, local_printing_queue, verbosity)
            else:
                dns_token = tokens_dictionary["dns"]
                if not is_integer(dns_token):
                    dns_token.set()
                    tokens_dictionary["dns"] = 0
        case "http":
            if type_of_action and tokens_dictionary["http"] == 0:
                tokens_dictionary["http"] = start_http_server_thread(interface_pc, local_printing_queue, verbosity)
            else:
                http_token = tokens_dictionary["http"]
                if not is_integer(http_token):
                    stop_server(local_printing_queue)
                    tokens_dictionary["http"] = 0
        case "proxy":
            if type_of_action and tokens_dictionary["dns"] == 0:
                tokens_dictionary["proxy"] = start_mitm_proxy_thread(local_printing_queue, verbosity)
            else:
                proxy_token = tokens_dictionary["proxy"]
                if not is_integer(proxy_token):
                    proxy_token.set()
                    tokens_dictionary["proxy"] = 0


def start_gui(interface_pc_, mac_address_, ip_address_, router_ip_, verbosity_, local_printing_queue_):
    global interface_pc
    global mac_address
    global targeted_ip
    global router_ip
    global verbosity
    global local_printing_queue

    interface_pc = interface_pc_
    mac_address = mac_address_
    targeted_ip = ip_address_
    router_ip = router_ip_
    verbosity = verbosity_
    local_printing_queue = local_printing_queue_

    root = tk.Tk()

    root.tk.call('source', './assets/gui_theme/forest-dark.tcl')
    ttk.Style().theme_use('forest-dark')

    root.title('Advanced Sniffer')
    root.iconbitmap('')
    root.geometry('450x670')
    root.resizable(False, False)

    spacing_label = Label(root, text="                             ")

    target_ip_label = Label(root, text="Target ip").grid(row=0, column=0)
    spacing_label.grid(row=0, column=1)
    gateway_ip_label = Label(root, text="Gateway ip").grid(row=0, column=2)

    target_ip_entry = ttk.Entry()
    target_ip_entry.grid(row=1, column=0, columnspan=2)
    gateway_ip_entry = ttk.Entry()
    gateway_ip_entry.grid(row=1, column=2, columnspan=2)

    modules_label = Label(root, text="Modules").grid(row=2, column=0)
    spacing_label.grid(row=1, column=1)
    actions_label = Label(root, text="Actions").grid(row=2, column=2)

    arp_poisoning_label = Label(root, text="Arp poisoning").grid(row=3, column=0)
    spacing_label.grid(row=3, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("arp", 1, target_ip_entry, gateway_ip_entry)).grid(row=3, column=2,
                                                                                                   padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("arp", 0, target_ip_entry, gateway_ip_entry)).grid(row=3, column=3,
                                                                                                 padx=5, pady=5)

    dns_spoofing_label = Label(root, text="DNS spoofing").grid(row=4, column=0)
    spacing_label.grid(row=4, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("dns", 1, target_ip_entry, gateway_ip_entry)).grid(row=4, column=2,
                                                                                                   padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("dns", 0, target_ip_entry, gateway_ip_entry)).grid(row=4, column=3,
                                                                                                 padx=5, pady=5)

    http_server_label = Label(root, text="HTTP server").grid(row=5, column=0)
    spacing_label.grid(row=5, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("http", 1, target_ip_entry, gateway_ip_entry)).grid(row=5, column=2,
                                                                                                    padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("http", 0, target_ip_entry, gateway_ip_entry)).grid(row=5, column=3,
                                                                                                  padx=5, pady=5)

    proxy_server_label = Label(root, text="Proxy server").grid(row=6, column=0)
    spacing_label.grid(row=6, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("proxy", 1, target_ip_entry, gateway_ip_entry)).grid(row=6, column=2,
                                                                                                     padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("proxy", 0, target_ip_entry, gateway_ip_entry)).grid(row=6, column=3,
                                                                                                   padx=5, pady=5)

    logging_input_field = tk.Text(width=50)
    set_text_for_printer(logging_input_field)
    logging_input_field.grid(row=7, column=0, rowspan=1, columnspan=4, padx=5, pady=5)

    root.mainloop()
