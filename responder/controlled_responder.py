#!/usr/bin/env python3
"""Private deterministic responder for the harmless WinST/DT fixture."""
import base64
import hashlib
import json
import os
import ssl
import socket
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

MARKER = "WINSTDT-CONTROLLED-CANARY/1"
LOG = "/var/log/winstdt-responder/requests.jsonl"
KEY = "/etc/winstdt-responder/receipt_ed25519"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign(payload):
    with tempfile.NamedTemporaryFile() as message:
        message.write(payload)
        message.flush()
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", KEY,
                        "-n", "winstdt-responder", message.name],
                       check=True, capture_output=True)
        signature = open(message.name + ".sig", "rb").read()
        os.unlink(message.name + ".sig")
    return base64.b64encode(signature).decode()


class Handler(BaseHTTPRequestHandler):
    server_version = "WinSTDTControlledResponder/1"

    def log_message(self, *_args):
        return

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16384:
                raise ValueError("invalid body length")
            body = self.rfile.read(length)
            request = json.loads(body)
            if set(request) != {"marker", "run_id", "sequence", "canary"}:
                raise ValueError("unexpected fields")
            if request["marker"] != MARKER or request["sequence"] not in (1, 2, 3):
                raise ValueError("invalid controlled request")
            receipt = {"schema_version": "1.0", "run_id": str(request["run_id"]),
                       "sequence": request["sequence"],
                       "request_sha256": hashlib.sha256(body).hexdigest(),
                       "canary_sha256": hashlib.sha256(str(request["canary"]).encode()).hexdigest(),
                       "received_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
            receipt["signature"] = sign(canonical(receipt))
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            with open(LOG, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({**receipt, "source_ip": self.client_address[0]}, sort_keys=True) + "\n")
            encoded = canonical(receipt) + b"\n"
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
        except (ValueError, json.JSONDecodeError, subprocess.CalledProcessError):
            self.send_error(400, "controlled request rejected")

    def do_GET(self):
        if self.path != "/receipts" or self.client_address[0] != "192.168.125.1":
            self.send_error(404); return
        encoded = open(LOG, "rb").read() if os.path.exists(LOG) else b""
        self.send_response(200); self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)


def dns_response(query):
    if len(query) < 12:
        return b""
    index, labels = 12, []
    while index < len(query) and query[index]:
        size = query[index]; labels.append(query[index + 1:index + 1 + size].decode("ascii", "ignore"))
        index += size + 1
    end = index + 5
    if end > len(query) or ".".join(labels).lower() != "validation.winstdt.test":
        return query[:2] + b"\x81\x83" + query[4:6] + b"\0\0\0\0\0\0" + query[12:end]
    return (query[:2] + b"\x81\x80" + query[4:6] + b"\0\x01\0\0\0\0" + query[12:end] +
            b"\xc0\x0c\0\x01\0\x01\0\0\0\x1e\0\x04" + socket.inet_aton("192.168.125.10"))


def serve_dns():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("192.168.125.10", 53))
    while True:
        query, peer = udp.recvfrom(4096); udp.sendto(dns_response(query), peer)


def serve_dns_tcp():
    listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("192.168.125.10", 53)); listener.listen(8)
    while True:
        connection, _peer = listener.accept()
        with connection:
            length = connection.recv(2)
            if len(length) == 2:
                query = connection.recv(struct.unpack("!H", length)[0])
                response = dns_response(query); connection.sendall(struct.pack("!H", len(response)) + response)


def serve(port, tls=False):
    server = ThreadingHTTPServer(("192.168.125.10", port), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/etc/winstdt-responder/tls.crt", "/etc/winstdt-responder/tls.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


Thread(target=serve_dns, daemon=True).start()
Thread(target=serve_dns_tcp, daemon=True).start()
Thread(target=serve, args=(8443, True), daemon=True).start()
serve(8080)
