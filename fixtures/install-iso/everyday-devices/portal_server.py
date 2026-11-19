# SPDX-License-Identifier: MIT
"""Guest network-namespace HTTP endpoint, with no external route or credentials."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        counter = Path(sys.argv[1] + '.count')
        counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
        mode = Path(sys.argv[1]).read_text().strip()
        if mode == 'offline':
            self.connection.close()
            return
        body = b'NetworkManager is online' if mode == 'online' else b'Sign in to the fixture network'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(('10.77.0.1', 80), Handler).serve_forever()
