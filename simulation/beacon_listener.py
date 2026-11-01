#!/usr/bin/env python3
"""
INC-003 — Beacon listener.
Run on KALI-ATK01 (192.168.56.50) before executing malware_sim.ps1 on
WIN-FS01. Listens on :8080 and logs each incoming beacon request with a
timestamp, purely so you have a terminal-output screenshot of the
outbound connections being received. No action is taken on the requests.

Usage:
    python3 beacon_listener.py
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

LISTEN_PORT = 8080
LOG_PATH = "beacon_listener.log"


class BeaconHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ts = datetime.now(timezone.utc).isoformat()
        line = f"{ts} beacon received from {self.client_address[0]} path={self.path}"
        print(line)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ack")

    def log_message(self, format, *args):
        pass  # suppress default stderr logging, we log explicitly above


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), BeaconHandler)
    print(f"[*] Beacon listener on 0.0.0.0:{LISTEN_PORT}. Logging to {LOG_PATH}. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
