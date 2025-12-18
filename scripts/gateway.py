#!/usr/bin/env python3
"""Simple HTTP gateway that forwards requests to the CLI client.

POST /send
  JSON body: { "mode": "http" | "message", "path": "/", "host": "example.com", "dest": "IP:PORT", "message": "..." }

Returns: 200 with client stdout as body, or 4xx/5xx on error.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import subprocess
import argparse
from urllib.parse import urlparse

class GatewayHandler(BaseHTTPRequestHandler):
    def _check_api_key(self):
        # If GATEWAY_API_KEY is set in environment, require X-API-Key header
        import os
        required = os.environ.get('GATEWAY_API_KEY')
        if not required:
            return True
        key = self.headers.get('X-API-Key')
        return key == required

    def _send_json(self, code, obj):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        body = json.dumps(obj).encode('utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._check_api_key():
            return self._send_json(401, {'error': 'unauthorized'})

        if self.path != '/send':
            return self._send_json(404, {'error': 'not found'})

        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode('utf-8'))
        except Exception:
            return self._send_json(400, {'error': 'invalid json'})

        mode = data.get('mode')
        dest = data.get('dest')
        if not dest:
            return self._send_json(400, {'error': 'missing dest'})

        if mode == 'http':
            path = data.get('path', '/')
            host = data.get('host') or dest.split(':',1)[0]
            cmd = ['python', 'cli/client.py', '--http-get', path, '--http-host', host, '--dest', dest, '--no-open']
        elif mode == 'message':
            message = data.get('message', '')
            cmd = ['python', 'cli/client.py', '--message', message, '--dest', dest]
        else:
            return self._send_json(400, {'error': 'invalid mode'})

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return self._send_json(504, {'error': 'client timeout'})

        if proc.returncode != 0:
            return self._send_json(502, {'error': 'client failed', 'stdout': proc.stdout, 'stderr': proc.stderr})

        # Success: return stdout
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        out = proc.stdout or ''
        self.send_header('Content-Length', str(len(out.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(out.encode('utf-8'))

    def do_GET(self):
        # health check
        if self.path == '/health':
            return self._send_json(200, {'status': 'ok'})
        return self._send_json(404, {'error': 'not found'})


def run(addr, port):
    server = HTTPServer((addr, port), GatewayHandler)
    print(f"Gateway listening on {addr}:{port}")
    server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default='0.0.0.0:8080', help='listen address:port')
    args = parser.parse_args()
    host, prt = args.listen.split(':',1)
    run(host, int(prt))
