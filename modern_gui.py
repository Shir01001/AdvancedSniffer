import tkinter as tk
from tkinter import ttk, Label, Entry

from arp_poisoning import start_arp_poisoning
from http_server import start_http_server_thread
# from packet_analysis import start_sniffer_thread
from dns_poisoning import start_dns_poisoning
from mitm_proxy import start_mitm_proxy_thread


tokens_dictionary = {"arp": 0, "dns": 0, "http": 0, "proxy": 0}

def gui_callback(option_for_action, type_of_action):
    match option_for_action:
        case "arp":
            if type_of_action:
                print(option_for_action + ' ' + str(type_of_action))

            else:
                print(option_for_action + ' ' + str(type_of_action))
        case "dns":
            if type_of_action:
                print(option_for_action + ' ' + str(type_of_action))
            else:
                print(option_for_action + ' ' + str(type_of_action))
        case "http":
            if type_of_action:
                print(option_for_action + ' ' + str(type_of_action))
            else:
                print(option_for_action + ' ' + str(type_of_action))
        case "proxy":
            if type_of_action:
                print(option_for_action + ' ' + str(type_of_action))
            else:
                print(option_for_action + ' ' + str(type_of_action))


def start_gui():
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

    target_ip_entry = ttk.Entry().grid(row=1, column=0, columnspan=2)
    gateway_ip_entry = ttk.Entry().grid(row=1, column=2, columnspan=2)

    modules_label = Label(root, text="Modules").grid(row=2, column=0)
    spacing_label.grid(row=1, column=1)
    actions_label = Label(root, text="Actions").grid(row=2, column=2)

    arp_poisoning_label = Label(root, text="Arp poisoning").grid(row=3, column=0)
    spacing_label.grid(row=3, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("arp", 1)).grid(row=3, column=2,
                                                                                                   padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("arp", 0)).grid(row=3, column=3,
                                                                                                 padx=5, pady=5)

    dns_spoofing_label = Label(root, text="DNS spoofing").grid(row=4, column=0)
    spacing_label.grid(row=4, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("dns", 1)).grid(row=4, column=2,
                                                                                                   padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("dns", 0)).grid(row=4, column=3,
                                                                                                 padx=5, pady=5)

    http_server_label = Label(root, text="HTTP server").grid(row=5, column=0)
    spacing_label.grid(row=5, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("http", 1)).grid(row=5, column=2,
                                                                                                    padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("http", 0)).grid(row=5, column=3,
                                                                                                  padx=5, pady=5)

    proxy_server_label = Label(root, text="Proxy server").grid(row=6, column=0)
    spacing_label.grid(row=6, column=1)
    start_button_arp = ttk.Button(root, text='start', command=lambda: gui_callback("proxy", 1)).grid(row=6, column=2,
                                                                                                     padx=5, pady=5)
    stop_button_arp = ttk.Button(root, text="stop", command=lambda: gui_callback("proxy", 0)).grid(row=6, column=3,
                                                                                                   padx=5, pady=5)

    logging_input_field = tk.Text(width=50).grid(row=7, column=0, rowspan=1, columnspan=4, padx=5, pady=5)

    root.mainloop()
