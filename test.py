"""interactive_lab.py

Interactive local test harness (REAL mode only).

Starts:
- directory server (node directory_server.js)
- N relay nodes (python relay/relay_node.py)
- destination TCP echo server (in-process) that replies with ACK:<message>\n
Then lets you send multiple messages and see the response printed by the CLI.

Usage:
  python interactive_lab.py
  python interactive_lab.py --hops 3 --dest 127.0.0.1:9000

Stop:
- Ctrl+C to shut down child processes.
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


def wait_relay_count(directory_base_url: str, expected: int, timeout_s: float = 20.0) -> None:
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


def autodetect_matryoshka_dll() -> Optional[str]:
    candidates = [
        ROOT / "dlls" / "Matryoshka.dll",
        ROOT / "dlls" / "matryoshka.dll",
        ROOT / "Matryoshka.dll",
        ROOT / "matryoshka.dll",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()

    # Network config
    parser.add_argument("--advertise-ip", type=str, default="127.0.0.1", help="IP address to register in the directory")
    parser.add_argument("--directory-port", type=int, default=5000, help="Directory server port")
    parser.add_argument("--directory", type=str, default=None, help="Directory base URL (overrides --advertise-ip/--directory-port)")

    parser.add_argument("--hops", type=int, default=3, help="Number of relays")
    parser.add_argument("--relay-base-port", type=int, default=8001, help="First relay TCP port")

    # Destination
    parser.add_argument("--dest", type=str, default="127.0.0.1:9000", help="Destination ip:port")
    parser.add_argument("--no-listener", action="store_true", help="Do not start the built-in echo listener (use an external server)")

    # Payload mode
    parser.add_argument("--http", action="store_true", help="Treat each input line as an HTTP path and send a GET request")
    parser.add_argument("--http-host", type=str, default=None, help="Host header to use for HTTP mode (default: destination IP)")

    # Crypto
    parser.add_argument("--dll", type=str, default=None, help="Path to Matryoshka.dll (default: ./dlls/Matryoshka.dll)")

    args = parser.parse_args()

    directory_base = args.directory or f"http://{args.advertise_ip}:{args.directory_port}"

    dll_path = args.dll or autodetect_matryoshka_dll()
    if not dll_path:
        raise RuntimeError("Matryoshka.dll not found. Put it in ./dlls or pass --dll.")

    dll_dir = str(Path(dll_path).resolve().parent)

    dest_ip, dest_port_s = args.dest.rsplit(":", 1)
    dest_port = int(dest_port_s)

    echo = None
    if not args.no_listener:
        # Start destination echo server (use --no-listener if you will run your own server, e.g. HTTP)
        echo = EchoServer(dest_ip, dest_port)
        echo.start()
        if not echo.wait_ready(5):
            raise RuntimeError("Echo server failed to start")

    # Reset directory relays file (fresh run)
    relays_json = ROOT / "directory-server" / "relays.json"
    try:
        relays_json.write_text("{}", encoding="utf-8")
    except Exception:
        pass

    # Start directory server
    dir_proc = subprocess.Popen(
        ["node", "directory_server.js"],
        cwd=str(ROOT / "directory-server"),
        env={
            **os.environ,
            "PORT": str(args.directory_port),
        },
    )

    relay_procs: list[subprocess.Popen] = []

    try:
        wait_http_ok(directory_base.rstrip("/") + "/health", timeout_s=10)

        # Start relays
        for i in range(args.hops):
            relay_id = f"relay_{i+1}"
            relay_port = args.relay_base_port + i
            p = subprocess.Popen(
                [
                    sys.executable,
                    "relay_node.py",
                    "--id",
                    relay_id,
                    "--port",
                    str(relay_port),
                    "--directory",
                    directory_base,
                    "--ip",
                    args.advertise_ip,
                ],
                cwd=str(ROOT / "relay"),
                env={
                    **os.environ,
                    # ensure Matryoshka.dll dependencies load from /dlls for relay crypto
                    "MATRYOSHKA_DLL_PATH": dll_path,
                    "PATH": dll_dir + os.pathsep + os.environ.get("PATH", ""),
                },
            )
            relay_procs.append(p)

        wait_relay_count(directory_base, expected=args.hops, timeout_s=20)

        print("\n=== Local lab is up (REAL mode) ===")
        print(f"Directory:   {directory_base}")
        print(f"Relays:      {args.hops} (ports {args.relay_base_port}..{args.relay_base_port + args.hops - 1})")
        if args.no_listener:
            print(f"Destination: {args.dest} (external server)")
        else:
            print(f"Destination: {args.dest} (built-in echo listener)")
        print(f"DLL:         {dll_path}")
        if args.http:
            print("Type an HTTP path (e.g. / or /health). Type /quit to exit.\n")
        else:
            print("Type a message and press Enter. Type /quit to exit.\n")

        # Interactive send loop
        while True:
            msg = input("> ").rstrip("\n")
            if msg.strip() in ("/quit", "/exit"):
                break
            if not msg.strip():
                continue

            env = os.environ.copy()
            env["MATRYOSHKA_FORCE_REAL"] = "1"
            env["MATRYOSHKA_DIRECTORY_URL"] = directory_base
            env["MATRYOSHKA_DLL_PATH"] = dll_path
            env["PATH"] = dll_dir + os.pathsep + env.get("PATH", "")

            # Run CLI once per message (prints response)
            if args.http:
                host = args.http_host or dest_ip
                rc = subprocess.call(
                    [
                        sys.executable,
                        "client.py",
                        "--http-get",
                        msg,
                        "--http-host",
                        host,
                        "--dest",
                        args.dest,
                        "--verbose",
                    ],
                    cwd=str(ROOT / "cli"),
                    env=env,
                )
            else:
                rc = subprocess.call(
                    [
                        sys.executable,
                        "client.py",
                        "--message",
                        msg,
                        "--dest",
                        args.dest,
                        "--verbose",
                    ],
                    cwd=str(ROOT / "cli"),
                    env=env,
                )
            if rc != 0:
                print(f"[ERR] client exited with code {rc}")

        return 0

    finally:
        if echo is not None:
            echo.stop()

        for p in relay_procs:
            try:
                p.terminate()
            except Exception:
                pass

        try:
            dir_proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
