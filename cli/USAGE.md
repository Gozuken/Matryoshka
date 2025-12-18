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

To save the HTTP response (server-side use), use `--http-save`:

```bash
python cli/client.py --http-get / --dest 127.0.0.1:8000 --http-save out.html
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

## Deploying on a single VPS (for presentations)

If you're going to run the directory server and multiple relays on a single VPS (for demos or classroom presentation), here's a concise plan:

1. Provision an Ubuntu 22.04 VPS and copy the repo to it.
2. Install system dependencies (Python, node, npm) and the Python virtualenv.
3. Create `systemd` service files for the directory server and relay instances (examples are in `deploy/`).
4. Start the directory service and several relay instances (e.g. 3 relays on ports 8001..8003).
5. Open firewall ports (e.g. 5000 for directory, 8001..8003 for relays) and ensure your VPS public IP is used with `--advertise-ip` when starting tests.

I added `deploy/deploy_on_vps.sh` and `deploy/*.service` templates to help automate this. Run the script as root and pass your username and the repository path on the VPS:

```bash
sudo ./deploy/deploy_on_vps.sh ubuntu /home/ubuntu/matryoshka
```

After deploy, test with:

```bash
python test.py --advertise-ip <VPS_PUBLIC_IP> --directory-port 5000 --hops 3 --relay-base-port 8001
```

Be careful: a single-server setup is fine for demos, but it's not the same as a distributed network. Limit exposure and use firewall rules for safety.

## Allowing external clients to use your relays

Two approaches to let outsiders (e.g., your classmates or teacher) use the relays running on your VPS:

Security: the gateway supports an API key. Set `GATEWAY_API_KEY` in the gateway's systemd unit or environment; clients must send header `X-API-Key: <key>` with requests. Without a key set the gateway is open (not recommended).

1. Direct client usage (recommended for demos):
	- Make sure the directory server (`/relays`) is reachable from the outside (open port 5000).
	- Run relay instances with the `--ip <VPS_PUBLIC_IP>` flag so they register the public IP in the directory.
	- Tell external users to run the client locally and point it to your directory server:

```bash
export MATRYOSHKA_DIRECTORY_URL=http://<VPS_PUBLIC_IP>:5000
python cli/client.py --http-get / --dest <VPS_PUBLIC_IP>:8001
```

2. Gateway (HTTP listener) — allow simple HTTP POST requests to trigger the client on the server:
	- Start the gateway on the VPS:

```bash
python scripts/gateway.py --listen 0.0.0.0:8080
```

	- External users can POST a simple JSON payload to `http://<VPS_PUBLIC_IP>:8080/send`:

```json
{
  "mode": "http",
  "path": "/",
  "host": "127.0.0.1",
  "dest": "<VPS_PUBLIC_IP>:8001"
}
```

	- The gateway runs the CLI client on the server (without opening a browser) and returns the client's stdout as the HTTP response. This is a convenient way to let non-technical users trigger requests through your relays without installing the full repo.

Security notes:
- Gateways should be restricted (firewall, IP allowlist, or simple auth) before exposing them publicly.
- The gateway supports an API key: set it with `sudo systemctl set-environment GATEWAY_API_KEY=yourkey` and then `sudo systemctl restart matryoshka-gateway`.
- Avoid letting untrusted users craft arbitrary payloads; for demos, restrict gateway access to your local network or specific IPs.

## Troubleshooting

- If you see warnings like `[Core Warning] Response layer decryption failed`, the client will fall back to returning the raw response bytes; HTML may still be detected and opened.
- If `requests` is missing: `pip install requests`.
- If the directory server is down, the client will fail by default. You can re-enable mock fallback (for offline testing) by setting `ALLOW_MOCK_FALLBACK=1` in the environment, but this is disabled by default.

### Windows / DLL errors

If you get an error when loading `Matryoshka.dll` (FileNotFoundError or dependency load error), either:

- Install the Visual C++ Redistributable (x64) matching the DLL build (required native dependencies), or
- Run in mock/fallback mode (no native DLL): ensure `MATRYOSHKA_FORCE_REAL` is not set and `ALLOW_MOCK_FALLBACK` is True. Example (Windows CMD):

```
set MATRYOSHKA_FORCE_REAL=0
python test.py --dest 127.0.0.1:9000 --hops 3
```

If the DLL exists but fails to load due to missing dependencies, tools like "Dependencies" (https://github.com/lucasg/Dependencies) or `dumpbin /dependents` can help diagnose what's missing.

### Console encoding errors (UnicodeEncodeError)

On Windows consoles you may see `UnicodeEncodeError` when log messages contain non-ASCII characters (e.g., Turkish letters). Two quick fixes:

- Run PowerShell/CMD with UTF-8 output (one-time):

```powershell
chcp 65001
$env:PYTHONUTF8 = 1
python relay/relay_node.py --id relay1 --port 8001 --directory http://127.0.0.1:5000 --ip <VPS_PUBLIC_IP>
```

- Or run the relay under the provided service which logs to `relay_node.log` encoded in UTF-8.

If you want, I can change log messages to avoid non-ASCII characters, or ensure log files/console are always UTF-8 (already applied to `relay_node.py`).

## Next steps and extensions

- Add SOCKS5 + streaming circuit support to enable HTTPS browsing through the onion network.
- Add `--http-save <file>` to `client.py` to save HTTP responses to a named file when routing through relays.

If you'd like, I can add either of the above features — which would you prefer next?

---
This file supplements the existing `cli/README.md` (Turkish). If you want, I can merge this into that file or replace it with a bilingual README.
