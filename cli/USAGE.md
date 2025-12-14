# Matryoshka CLI — Usage Guide

This document explains how to use the `cli` client (`client.py`) to send messages and fetch HTTP content through the Matryoshka testbed (local relays or mock mode).

## Requirements

- Python 3.8+
- `requests` (install with `pip install -r requirements.txt`)

## Running the client

### Interactive mode (default)

Run:

```bash
python cli/client.py
```

You will be prompted for a message and a destination (`IP:PORT`). The client will build a circuit, send the message, and print any response.

### Non-interactive modes

Send a raw message:

```bash
python cli/client.py --message "Hello" --dest 127.0.0.1:9000
```

Send an HTTP GET request (treats the `--http-get` value as the HTTP path):

```bash
python cli/client.py --http-get / --http-host example.com --dest 127.0.0.1:8000
```

Behavior:
- The client builds a circuit and sends the HTTP request through it.
- If the response contains an `HTTP/` response and appears to be HTML, the client will save the HTML to a temporary file and open it in your default web browser.

Notes:
- Use two dashes for long options: `--dest` (not `-dest`).
- For verbose output add `--verbose`.

## Direct file downloads (no relays)

If you only need to fetch files directly (no anonymity/relays), use the helper script:

```bash
python scripts/fetch_http.py --url http://127.0.0.1:8000/path/file.bin --output downloaded.bin
```

This uses `requests` and is binary-safe.

## Using a browser through the Matryoshka network (experimental)

There is a minimal HTTP proxy you can run locally which forwards HTTP requests via Matryoshka circuits:

```bash
python scripts/matryoshka_http_proxy.py --listen 127.0.0.1:8888
```

Then configure your browser's HTTP proxy to `127.0.0.1:8888` and visit plain `http://` sites. Limitations:

- Only plain HTTP is supported (no HTTPS CONNECT/tunneling yet).
- This proxy uses the `send_through_circuit_bytes` API; in mock mode it returns an HTTP-like response for testing.

If you want full browser support (including HTTPS), we can implement SOCKS5 + streaming tunneling, but it requires more protocol work.

## Environment variables

- `MATRYOSHKA_DIRECTORY_URL`: Override the directory server URL (default `http://127.0.0.1:5000`).
- `MATRYOSHKA_DLL_PATH`: Path to `Matryoshka.dll` if you want REAL-mode usage of the native library.
- `MATRYOSHKA_FORCE_REAL=1`: Force REAL mode (fail if DLL or directory unavailable).

## Test harness

You can run the provided local test lab which starts a directory server, relays, and a destination echo server:

```bash
python test.py --dest 127.0.0.1:9000 --hops 3
```

To use HTTP mode in the lab (treat interactive input as HTTP paths):

```bash
python test.py --dest 127.0.0.1:8000 --http
```

Type `/` or `/index.html` at the prompt to send an HTTP GET through the relays. If the response contains HTML it will be opened in your browser.

## Troubleshooting

- If you see warnings like `[Core Warning] Response layer decryption failed`, the client will fall back to returning the raw response bytes; HTML may still be detected and opened.
- If `requests` is missing: `pip install requests`.
- If the directory server is down, the client uses a mock relay list by default (controlled by `ALLOW_MOCK_FALLBACK` in `cli/core/circuit_builder.py`).

## Next steps and extensions

- Add SOCKS5 + streaming circuit support to enable HTTPS browsing through the onion network.
- Add `--http-save <file>` to `client.py` to save HTTP responses to a named file when routing through relays.

If you'd like, I can add either of the above features — which would you prefer next?

---
This file supplements the existing `cli/README.md` (Turkish). If you want, I can merge this into that file or replace it with a bilingual README.
