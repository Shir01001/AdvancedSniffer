import subprocess
import threading

from colorama import init, Fore

init()
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
RESET = Fore.RESET

def start_mitm_proxy(printing_queue, verbosity, cancel_token):
    printing_queue.put(f"{GREEN}[+] Mitm proxy thread started{RESET}")
    command = "./assets/binaries/mitmdump --listen-host 192.168.2.113 --listen-port 8080 --flow-detail 4"
    proc = subprocess.Popen(command.split(), stdout=subprocess.PIPE)

    while not cancel_token.is_set():
        if verbosity>0:
            if proc.stdout.readline() != b'':
                printing_queue.put(proc.stdout.readline().decode("UTF-8"))


def start_mitm_proxy_thread(printing_queue, verbosity):
    cancel_token = threading.Event()
    mitm_proxy_thread = threading.Thread(target=start_mitm_proxy, args=(printing_queue, verbosity, cancel_token))
    mitm_proxy_thread.start()
    return cancel_token
