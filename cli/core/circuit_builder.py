# core/circuit_builder.py
"""
Matryoshka Anonymous Messenger - Circuit Builder Module
Core networking functionality for building circuits and sending messages.
(Hybrid Mode: Works with REAL servers or fails over to SIMULATION)
"""

import base64
import ctypes
import json
import os
import random
import socket
import time
from typing import List, Dict, Optional, Tuple, Any

import requests
from requests.exceptions import RequestException

# Response encryption için
try:
    from .response_crypto import generate_response_keys, encrypt_response_layer, decrypt_response_layer
except ImportError:
    # Fallback: basit implementasyon
    def generate_response_keys(num_relays: int):
        return [(os.urandom(32), os.urandom(16)) for _ in range(num_relays)]
    
    def encrypt_response_layer(response: bytes, key: bytes, iv: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded = padder.update(response) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()
    
    def decrypt_response_layer(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

# --- HİBRİT MOD AYARLARI ---
# Gerçek sunucular yoksa testi etkinleştirir
ALLOW_MOCK_FALLBACK = True

# 1: her zaman C++/REAL dene, başarısızsa hata ver
# 0: C++/REAL dene, olmazsa mock'a düş (mock fallback is disabled by default)
FORCE_REAL = os.environ.get("MATRYOSHKA_FORCE_REAL", "0") == "1"

# By default do NOT fall back to MOCK relays. Set `ALLOW_MOCK_FALLBACK=1` to re-enable mock mode.
ALLOW_MOCK_FALLBACK = os.environ.get("ALLOW_MOCK_FALLBACK", "0") == "1"

class Circuit:
    """Represents a multi-hop circuit through relay nodes.

    Hybrid:
    - MOCK mode: relays[] contains fake entries.
    - REAL mode: entry_ip/entry_port/encrypted_payload are set (from matryoshka.dll).
    """

    def __init__(
        self,
        relays: Optional[List[Dict[str, Any]]] = None,
        circuit_id: Optional[str] = None,
        entry_ip: Optional[str] = None,
        entry_port: Optional[int] = None,
        encrypted_payload: Optional[bytes] = None,
        hop_count: Optional[int] = None,
    ):
        self.relays = relays or []
        self.circuit_id = circuit_id or self._generate_circuit_id()
        self.created_at = time.time()
        self.message_count = 0

        # REAL-mode fields
        self.entry_ip = entry_ip
        self.entry_port = entry_port
        self.encrypted_payload = encrypted_payload
        self.hop_count = hop_count
        
        # Response encryption key'leri (her relay için bir tane)
        # Entry'den exit'e sırayla: [entry_key, middle_key, exit_key]
        self.response_keys: Optional[List[Tuple[bytes, bytes]]] = None
    
    def _generate_circuit_id(self) -> str:
        return f"circuit_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
    
    def __len__(self) -> int:
        if self.hop_count:
            return int(self.hop_count)
        return len(self.relays)
    
    def __repr__(self) -> str:
        mode = "REAL" if self.encrypted_payload else "MOCK"
        return f"Circuit(id={self.circuit_id}, hops={len(self)}, mode={mode})"


def query_directory_for_relays(directory_url: str = "http://localhost:5000/relays") -> List[Dict[str, Any]]:
    """Query the directory server for available relays."""
    print(f"[Core] Querying directory: {directory_url}...")
    try:
        response = requests.get(directory_url, timeout=2)
        response.raise_for_status()
        data = response.json()
        return data.get("relays", [])
        
    except Exception as e:
        if ALLOW_MOCK_FALLBACK and not FORCE_REAL:
            print(f"[Core Warning] Directory server unreachable ({e}). Using MOCK relays.")
            # Sunucu yoksa sahte relay listesi döndür
            return [
                {'ip': '192.168.1.10', 'port': 9000, 'id': 'relay1'},
                {'ip': '10.0.0.5', 'port': 8888, 'id': 'relay2'},
                {'ip': '172.16.0.3', 'port': 9001, 'id': 'relay3'},
                {'ip': '192.168.1.20', 'port': 9002, 'id': 'relay4'},
                {'ip': '10.0.0.8', 'port': 8889, 'id': 'relay5'}
            ]
        return []

def _find_default_dll() -> Optional[str]:
    env_path = os.environ.get("MATRYOSHKA_DLL_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    if os.name == "nt":
        lib_filenames = ["matryoshka.dll", "Matryoshka.dll"]
    else:
        lib_filenames = ["libmatryoshka.so"]

    here = os.path.dirname(__file__)  # cli/core
    cli_dir = os.path.abspath(os.path.join(here, ".."))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))

    candidates: list[str] = []
    for name in lib_filenames:
        candidates.extend(
            [
                os.path.join(os.getcwd(), name),
                os.path.join(here, name),
                os.path.join(cli_dir, name),
                os.path.join(repo_root, name),
                os.path.join(repo_root, "dlls", name),
            ]
        )

    for p in candidates:
        if os.path.exists(p):
            return p

    return None


def _load_matryoshka_lib() -> Optional[ctypes.CDLL]:
    dll_path = _find_default_dll()
    if not dll_path:
        return None

    dll_abs = os.path.abspath(dll_path)
    if os.name == "nt":
        try:
            os.add_dll_directory(os.path.dirname(dll_abs))
        except Exception:
            pass

    # Diagnostic: attempt to load and if it fails, print helpful info
    try:
        lib = ctypes.CDLL(dll_abs)
    except Exception as e:
        # Provide extra context to help debug load failures on servers
        try:
            import platform, traceback, sys, getpass
            print(f"[DLL Diagnostic] Trying to load: {dll_abs}")
            print(f"[DLL Diagnostic] exists: {os.path.exists(dll_abs)}")
            print(f"[DLL Diagnostic] platform: {platform.system()} {platform.release()} ({platform.machine()})")
            print(f"[DLL Diagnostic] python: {sys.version.splitlines()[0]} ({platform.architecture()})")
            print(f"[DLL Diagnostic] process pid: {os.getpid()} cwd: {os.getcwd()} user: {getpass.getuser()}")

            # Show the directory and PATH snippets
            dll_dir = os.path.dirname(dll_abs)
            try:
                listing = os.listdir(dll_dir)
                print(f"[DLL Diagnostic] files in dll_dir: {listing[:20]}")
            except Exception as _:
                print("[DLL Diagnostic] could not list dll_dir contents")

            print(f"[DLL Diagnostic] dll_dir: {dll_dir}")
            print(f"[DLL Diagnostic] PATH contains dll_dir: {dll_dir in os.environ.get('PATH','')}")
            print(f"[DLL Diagnostic] PATH (start): {os.environ.get('PATH','')[:400]}")
            print(f"[DLL Diagnostic] ctypes.CDLL raised: {e}")
            tb = traceback.format_exc()
            print(f"[DLL Diagnostic] traceback:\n{tb}")

            # Try adding the dll dir and retry once (available on py3.8+)
            try:
                os.add_dll_directory(dll_dir)
                lib = ctypes.CDLL(dll_abs)
                print("[DLL Diagnostic] retry after add_dll_directory succeeded!")
                return lib
            except Exception as e2:
                print(f"[DLL Diagnostic] retry also failed: {e2}")
                return None
        except Exception:
            pass
        return None

    return lib


def _build_circuit_cpp(num_relays: int, message: str, destination: str, directory_url: str) -> Circuit:
    """Build a circuit using matryoshka.dll's build_circuit function."""
    lib = _load_matryoshka_lib()
    if not lib:
        raise RuntimeError("matryoshka.dll/libmatryoshka.so not found or could not be loaded")

    # Set up function signatures (match C ABI in cryptography/Matryoshka.cpp)
    lib.matryoshka_build_circuit_json_c.argtypes = [
        ctypes.c_int,        # num_relays
        ctypes.c_char_p,     # payload pointer
        ctypes.c_int,        # payload length
        ctypes.c_char_p,     # destination
        ctypes.c_char_p,     # directory_url
        ctypes.POINTER(ctypes.c_char_p)  # out_json
    ]
    lib.matryoshka_build_circuit_json_c.restype = ctypes.c_int

    # Free buffer function exported by DLL
    lib.matryoshka_free_buffer.argtypes = [ctypes.c_void_p]
    lib.matryoshka_free_buffer.restype = None

    out_json = ctypes.c_char_p()
    msg_bytes = message.encode('utf-8')
    # Use an explicit buffer to ensure memory remains alive during the C call
    msg_buf = ctypes.create_string_buffer(msg_bytes, len(msg_bytes))

    rc = lib.matryoshka_build_circuit_json_c(
        num_relays,
        msg_buf,  # char* to payload
        len(msg_bytes),
        destination.encode('utf-8'),
        directory_url.encode('utf-8'),
        ctypes.byref(out_json)
    )

    if rc != 0 or not out_json:
        raise RuntimeError(f"matryoshka_build_circuit_json_c failed with code {rc}")

    try:
        json_str = out_json.value.decode('utf-8')
        data = json.loads(json_str)
    finally:
        # Free the buffer returned by the DLL
        lib.matryoshka_free_buffer(ctypes.cast(out_json, ctypes.c_void_p))

    # Parse the JSON response (support both `entry_*` and `first_relay_*` names)
    entry_ip = data.get("entry_ip") or data.get("first_relay_ip")
    entry_port = data.get("entry_port") or data.get("first_relay_port")
    payload_b64 = data.get("encrypted_payload_b64")
    hop_count = data.get("hop_count")
    response_keys_data = data.get("response_keys", [])

    if not all([entry_ip, entry_port, payload_b64]):
        raise RuntimeError(f"Invalid circuit data from C++: keys present: {list(data.keys())}")

    encrypted_payload = base64.b64decode(payload_b64)

    # Parse response keys
    response_keys = []
    for rk in response_keys_data:
        key = base64.b64decode(rk["key_b64"])
        iv = base64.b64decode(rk["iv_b64"])
        response_keys.append((key, iv))

    circuit = Circuit(
        entry_ip=entry_ip,
        entry_port=entry_port,
        encrypted_payload=encrypted_payload,
        hop_count=hop_count
    )
    circuit.response_keys = response_keys

    return circuit


def build_circuit(num_relays: int = 3, directory_url: str = "http://localhost:5000/relays") -> Circuit:
    """Build a circuit through relay nodes.
    
    REAL mode:
    - returns a shell Circuit that will be populated during send
    
    MOCK mode:
    - queries directory and returns a Circuit with relays[] list
    """
    directory_base_url = directory_url
    if directory_base_url.endswith("/relays"):
        directory_base_url = directory_base_url[:-len("/relays")]

    # Try REAL mode first if DLL is available
    try:
        if _find_default_dll():
            # Return a shell circuit; actual build happens in send_through_circuit
            return Circuit(hop_count=num_relays)
    except Exception as e:
        if FORCE_REAL:
            raise
        if not ALLOW_MOCK_FALLBACK:
            raise
        print(f"[Core Warning] REAL mode unavailable ({e}). Using MOCK relays.")

    # --- MOCK fallback ---
    all_relays = query_directory_for_relays(directory_url)
    if not all_relays:
        raise RuntimeError("No relays available from directory server")

    if len(all_relays) < num_relays and ALLOW_MOCK_FALLBACK:
        while len(all_relays) < num_relays:
            all_relays.append(all_relays[0])  # Test için kopyala

    if len(all_relays) < num_relays:
        raise RuntimeError(f"Not enough relays. Found {len(all_relays)}, need {num_relays}")

    selected_relays = random.sample(all_relays, num_relays)
    if ALLOW_MOCK_FALLBACK:
        time.sleep(1)

    return Circuit(relays=selected_relays)

def send_through_circuit(circuit: Circuit, message: str, destination: str, directory_url: Optional[str] = None) -> Optional[str]:
    """Send a message through the circuit to the destination.

    REAL mode:
    - builds encrypted onion using matryoshka.dll
    - connects to entry relay via TCP
    - reads response (newline-terminated) and returns it

    MOCK mode:
    - simulated delays + canned response
    """
    if not circuit:
        raise ValueError("Invalid circuit")

    # Normalize directory URL
    directory_base_url = directory_url or os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")
    if directory_base_url.endswith("/relays"):
        directory_base_url = directory_base_url[:-len("/relays")]

    # Try REAL mode
    try:
        if _find_default_dll():
            try:
                # Build the encrypted circuit with the message and destination
                real_circuit = _build_circuit_cpp(len(circuit), message, destination, directory_base_url)
                
                print(f"[Core] Connecting to entry relay: {real_circuit.entry_ip}:{real_circuit.entry_port}")
                print(f"[Core] Payload size: {len(real_circuit.encrypted_payload)} bytes")
                
                # Create TCP socket and connect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)  # Increased timeout to 30 seconds
                
                try:
                    sock.connect((real_circuit.entry_ip, real_circuit.entry_port))
                    print(f"[Core] Connected to {real_circuit.entry_ip}:{real_circuit.entry_port}")
                    
                    # Send the encrypted payload
                    sock.sendall(real_circuit.encrypted_payload)
                    print(f"[Core] Sent {len(real_circuit.encrypted_payload)} bytes")
                    
                    # Signal end of transmission
                    try:
                        sock.shutdown(socket.SHUT_WR)
                        print(f"[Core] Signaled end of transmission")
                    except Exception as e:
                        print(f"[Core Warning] Could not shutdown socket for writing: {e}")

                    # Read response until EOF
                    print(f"[Core] Waiting for response...")
                    resp = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                        print(f"[Core] Received {len(chunk)} bytes (total: {len(resp)})")

                    print(f"[Core] Total response: {len(resp)} bytes")

                    # Decrypt response if we have keys
                    final_bytes = resp
                    if resp and real_circuit.response_keys:
                        try:
                            print(f"[Core] Decrypting response through {len(real_circuit.response_keys)} layers...")
                            final_bytes = _decrypt_response_layers(resp, real_circuit.response_keys)
                            print(f"[Core] Decrypted response: {len(final_bytes)} bytes")
                        except Exception as e:
                            print(f"[Core Warning] Response decryption failed: {e}, returning raw response")

                    # Return the response
                    if final_bytes.startswith(b"HTTP/"):
                        return final_bytes.decode("utf-8", errors="replace").strip()

                    return final_bytes.decode("utf-8", errors="replace").strip() if final_bytes else ""
                    
                finally:
                    sock.close()
                    print(f"[Core] Socket closed")
                    
            except Exception as e:
                print(f"[Core Error] Failed to send through circuit: {e}")
                import traceback
                traceback.print_exc()
                raise

        if FORCE_REAL:
            raise RuntimeError("FORCE_REAL enabled but matryoshka.dll unavailable")

    except Exception as e:
        if FORCE_REAL:
            raise
        if not ALLOW_MOCK_FALLBACK:
            raise
        print(f"[Core Warning] REAL send failed ({e}). Falling back to MOCK.")

    # --- MOCK fallback ---
    if not circuit.relays:
        raise ValueError("Invalid circuit (no relays in MOCK mode)")

    for _ in circuit.relays:
        time.sleep(0.3)

    return f"Message received by {destination} (Securely Delivered)"


def send_through_circuit_bytes(circuit: Circuit, message_bytes: bytes, destination: str, directory_url: Optional[str] = None) -> bytes:
    """Send raw bytes through the circuit and return raw bytes response.

    Returns raw response bytes (useful for HTTP proxying or binary downloads).
    """
    if not circuit:
        raise ValueError("Invalid circuit")

    directory_base_url = directory_url or os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")
    if directory_base_url.endswith("/relays"):
        directory_base_url = directory_base_url[:-len("/relays")]

    try:
        if _find_default_dll():
            try:
                # Build circuit with message bytes decoded as UTF-8
                real_circuit = _build_circuit_cpp(
                    len(circuit),
                    message_bytes.decode('utf-8', errors='replace'),
                    destination,
                    directory_base_url
                )

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                
                try:
                    sock.connect((real_circuit.entry_ip, real_circuit.entry_port))
                    sock.sendall(real_circuit.encrypted_payload)
                    
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

                    if resp and real_circuit.response_keys:
                        try:
                            resp = _decrypt_response_layers(resp, real_circuit.response_keys)
                        except Exception:
                            pass

                    return resp
                    
                finally:
                    sock.close()
                    
            except Exception as e:
                print(f"[Core Error] Failed to send bytes through circuit: {e}")
                raise

        if FORCE_REAL:
            raise RuntimeError("FORCE_REAL enabled but matryoshka.dll unavailable")

    except Exception as e:
        if FORCE_REAL:
            raise
        if not ALLOW_MOCK_FALLBACK:
            raise
        print(f"[Core Warning] REAL send failed ({e}). Falling back to MOCK.")

    # MOCK fallback: return a simple HTTP-like response bytes
    body = b"Message received by %b (Securely Delivered)" % destination.encode('utf-8')
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " + str(len(body)).encode('ascii') + b"\r\n\r\n" + body
    return resp


def _decrypt_response_layers(encrypted_response: bytes, response_keys: List[Tuple[bytes, bytes]]) -> bytes:
    """
    Response'u katman katman çözer (Tor benzeri).
    Her relay kendi katmanını eklediği için, ters sırada çözülür.
    
    Args:
        encrypted_response: Şifreli response (tüm katmanlar)
        response_keys: Her relay için (key, iv) tuple'ları (entry'den exit'e sırayla)
        
    Returns:
        Çözülmüş response bytes
    """
    current_data = encrypted_response
    
    # Ters sırada çöz (exit'ten entry'ye)
    # Entry relay en son şifrelediği için, ilk çözülür
    for key, iv in reversed(response_keys):
        try:
            current_data = decrypt_response_layer(current_data, key, iv)
        except Exception as e:
            # Bir katman çözülemezse, muhtemelen daha az katman var
            # Veya key yanlış, devam et
            print(f"[Core Warning] Response layer decryption failed: {e}")
            break
    
    return current_data
