#!/usr/bin/env python3
"""Simple HTTP fetcher for local testing.

Usage:
  python scripts/fetch_http.py --url http://127.0.0.1:8000/ --output out.html --render
  python scripts/fetch_http.py --host 127.0.0.1 --port 8000 --path /index.html
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import webbrowser
from pathlib import Path

import requests


def fetch_url(url: str, timeout: float = 5.0) -> requests.Response:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch HTTP content and optionally render it")
    parser.add_argument("--url", type=str, help="Full URL to fetch (e.g. http://127.0.0.1:8000/)")
    parser.add_argument("--output", type=Path, default=None, help="If provided, save response body to this file")
    parser.add_argument("--render", action="store_true", help="If provided and response looks like HTML, open it in the default browser")

    args = parser.parse_args(argv)

    if not args.url:
        parser.print_help()
        return 2

    try:
        r = fetch_url(args.url)
    except Exception as e:
        print(f"[ERR] Failed to fetch {args.url}: {e}")
        return 1

    body = r.content
    ct = r.headers.get("Content-Type", "")

    if args.output:
        args.output.write_bytes(body)
        print(f"Saved {len(body)} bytes to {args.output}")

    if args.render and ("html" in ct or args.output and args.output.suffix in {".html", ".htm"}):
        if args.output:
            webbrowser.open(args.output.resolve().as_uri())
        else:
            # write to temp file
            t = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
            t.write(body)
            t.flush()
            t.close()
            webbrowser.open("file://" + t.name)

    # Print body to stdout if not saved
    if not args.output:
        try:
            print(body.decode("utf-8", errors="replace"))
        except Exception:
            print(f"[OK] {len(body)} bytes received (binary)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
