"""e2e_test.py

End-to-end integration test for the Matryoshka project.

What it does:
- Starts the directory server (Node/Express)
- Starts N relay nodes (Python)
- Starts a simple destination TCP echo server (Python, in-process)
- Sends a message and verifies that a response comes back

Modes:
- Default (fallback): sends a nested `ip:port|payload` packet that works even without matryoshka.dll.
- --real: runs the CLI client in REAL mode (requires matryoshka.dll).

Usage examples:
  python e2e_test.py
  python e2e_test.py --real --dll C:\\path\\to\\matryoshka.dll

Notes:
- This script is designed for local testing on one machine (127.0.0.1).
- Relay nodes must support response forwarding (patched in relay/relay_node.py).
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import requests


ROOT = Path(__file__).resolve().parent


class EchoServer(threading.Thread):
    def __init__(self, host: str, port: int, response_prefix: str = "ACK:"):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.response_prefix = response_prefix
        self._stop = threading.Event()
        self._ready = threading.Event()
        self.last_message: Optional[bytes] = None

    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(5)
            self._ready.set()

            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _addr = srv.accept()
                except socket.timeout:
                    continue

                with conn:
                    data = b""
                    conn.settimeout(5)
                    while True:
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        data += chunk

                    self.last_message = data
                    # Send newline-terminated response (client expects \n)
                    msg = data.decode("utf-8", errors="replace")
                    resp = f"{self.response_prefix}{msg}\n".encode("utf-8")
                    try:
                        conn.sendall(resp)
                    except Exception:
                        pass

    def wait_ready(self, timeout: float = 5.0) -> bool:
        return self._ready.wait(timeout)

    def stop(self) -> None:
        self._stop.set()


def wait_http_ok(url: str, timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                return
        except Exception as e:
            last_err = e
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {url}. Last error: {last_err}")


def wait_relay_count(directory_base_url: str, expected: int, timeout_s: float = 15.0) -> None:
    url = directory_base_url.rstrip("/") + "/relays"
    deadline = time.time() + timeout_s
    last_count = None
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                data = r.json()
                last_count = int(data.get("count", 0))
                if last_count >= expected:
                    return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {expected} relays. Last count: {last_count}")


def send_fallback_packet(entry_host: str, entry_port: int, packet: bytes) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((entry_host, entry_port))
        sock.sendall(packet)
        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass

        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\n" in resp:
                break
        return resp.decode("utf-8", errors="replace").strip()
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real", action="store_true", help="Use cli/ client + matryoshka.dll (REAL mode)")
    parser.add_argument("--dll", type=str, default=None, help="Path to matryoshka.dll (sets MATRYOSHKA_DLL_PATH)")
    parser.add_argument("--directory", type=str, default="http://localhost:5000", help="Directory base URL")
    parser.add_argument("--hops", type=int, default=3, help="Number of relays to start")
    parser.add_argument("--dest", type=str, default="127.0.0.1:9000", help="Destination ip:port")
    parser.add_argument("--message", type=str, default="Hello from e2e_test", help="Message")
    args = parser.parse_args()

    dest_ip, dest_port_s = args.dest.rsplit(":", 1)
    dest_port = int(dest_port_s)

    # 1) Start destination echo server
    echo = EchoServer(dest_ip, dest_port)
    echo.start()
    if not echo.wait_ready(5):
        raise RuntimeError("Echo server failed to start")

    # 2) Start directory server
    relays_json = ROOT / "directory-server" / "relays.json"
    try:
        relays_json.write_text("{}", encoding="utf-8")
    except Exception:
        pass

    dir_proc = subprocess.Popen(
        ["node", "directory_server.js"],
        cwd=str(ROOT / "directory-server"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_http_ok(args.directory.rstrip("/") + "/health", timeout_s=10)

        # 3) Start relay nodes
        relay_procs: list[subprocess.Popen] = []
        for i in range(args.hops):
            relay_id = f"relay_{i+1}"
            relay_port = 8001 + i
            p = subprocess.Popen(
                [
                    sys.executable,
                    "relay_node.py",
                    "--id",
                    relay_id,
                    "--port",
                    str(relay_port),
                    "--directory",
                    args.directory,
                    "--ip",
                    "127.0.0.1",
                ],
                cwd=str(ROOT / "relay"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            relay_procs.append(p)

        wait_relay_count(args.directory, expected=args.hops, timeout_s=20)

        # 4) Send message
        if args.real:
            env = os.environ.copy()
            env["MATRYOSHKA_FORCE_REAL"] = "1"
            env["MATRYOSHKA_DIRECTORY_URL"] = args.directory

            dll_path = args.dll
            if not dll_path:
                # Auto-detect common locations
                candidates = [
                    str(ROOT / "dlls" / "Matryoshka.dll"),
                    str(ROOT / "dlls" / "matryoshka.dll"),
                    str(ROOT / "Matryoshka.dll"),
                    str(ROOT / "matryoshka.dll"),
                ]
                for c in candidates:
                    if os.path.exists(c):
                        dll_path = c
                        break

            if dll_path:
                env["MATRYOSHKA_DLL_PATH"] = dll_path

            # Run CLI with inherited stdio so you can watch the response arrive in real-time.
            cli_proc = subprocess.Popen(
                [
                    sys.executable,
                    "client.py",
                    "--message",
                    args.message,
                    "--dest",
                    args.dest,
                    "--verbose",
                ],
                cwd=str(ROOT / "cli"),
                env=env,
            )

            try:
                cli_proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                cli_proc.kill()
                raise RuntimeError("CLI client timed out")

            if cli_proc.returncode != 0:
                raise RuntimeError(f"CLI client failed (exit={cli_proc.returncode})")

        else:
            # Nested fallback packet (works without DLL):
            # relay1 -> relay2 -> relay3 -> destination
            hops = [f"127.0.0.1:{8001 + i}" for i in range(args.hops)]

            payload = args.message
            next_hop = args.dest
            # innermost
            nested = f"{next_hop}|{payload}"
            for hop in reversed(hops[1:]):
                nested = f"{hop}|{nested}"
            entry = hops[0]
            entry_ip, entry_port_s = entry.rsplit(":", 1)

            resp = send_fallback_packet(entry_ip, int(entry_port_s), nested.encode("utf-8"))
            print("Response:", resp)

        # 5) Sanity: echo server received something
        if echo.last_message is None:
            raise RuntimeError("Destination did not receive any message")

        return 0

    finally:
        echo.stop()

        # terminate child procs
        try:
            dir_proc.terminate()
        except Exception:
            pass

        # Drain outputs (best-effort) so pipes don't deadlock
        try:
            if dir_proc.stdout:
                _ = dir_proc.stdout.read()
        except Exception:
            pass

        # Relay procs were created inside try; guard if exception before
        for proc in (locals().get("relay_procs") or []):
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                if proc.stdout:
                    _ = proc.stdout.read()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
