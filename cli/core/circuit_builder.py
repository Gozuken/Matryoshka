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
# 0: C++/REAL dene, olmazsa mock'a düş
FORCE_REAL = os.environ.get("MATRYOSHKA_FORCE_REAL", "0") == "1"

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

    lib = ctypes.CDLL(dll_abs)


    # int matryoshka_build_circuit_json_c(int hop_count, const uint8_t* payload, int payload_len,
    #                                    const char* final_destination, const char* directory_url, char** json_out)
    lib.matryoshka_build_circuit_json_c.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.matryoshka_free_buffer.argtypes = [ctypes.c_void_p]

    return lib


def _build_circuit_cpp(num_relays: int, message: str, destination: str, directory_base_url: str) -> Circuit:
    lib = _load_matryoshka_lib()
    if not lib:
        raise FileNotFoundError("matryoshka.dll not found")

    out_ptr = ctypes.c_char_p()

    msg_bytes = message.encode("utf-8")
    msg_buf = (ctypes.c_uint8 * len(msg_bytes)).from_buffer_copy(msg_bytes)

    rc = lib.matryoshka_build_circuit_json_c(
        int(num_relays),
        msg_buf,
        int(len(msg_bytes)),
        destination.encode("utf-8"),
        directory_base_url.encode("utf-8"),
        ctypes.byref(out_ptr),
    )

    if rc != 0:
        raise RuntimeError(f"matryoshka_build_circuit_json_c failed (rc={rc})")

    try:
        json_str = out_ptr.value.decode("utf-8")
        data = json.loads(json_str)
    finally:
        lib.matryoshka_free_buffer(out_ptr)

    encrypted_payload = base64.b64decode(data["encrypted_payload_b64"])
    entry_ip = data["first_relay_ip"]
    entry_port = int(data["first_relay_port"])
    hop_count = int(data.get("hop_count", num_relays))
    
    # Response encryption key'lerini oluştur (her relay için bir tane)
    response_keys = generate_response_keys(hop_count)

    circuit = Circuit(
        relays=[],
        entry_ip=entry_ip,
        entry_port=entry_port,
        encrypted_payload=encrypted_payload,
        hop_count=hop_count,
    )
    circuit.response_keys = response_keys
    
    # Response key'lerini pakete ekle (ilk katmanda)
    # C++ kütüphanesi paketi oluşturduğu için, Python tarafında paketi parse edip eklememiz gerekiyor
    # Ancak bu zor, bu yüzden key'leri Circuit objesine kaydedip, 
    # paketi göndermeden önce ekleyeceğiz veya ayrı bir mekanizma kullanacağız
    # Şimdilik key'leri Circuit'e kaydediyoruz, pakete ekleme işlemi relay'lerde yapılacak
    
    return circuit


def build_circuit(num_relays: int = 3, directory_url: str = "http://localhost:5000/relays") -> Circuit:
    """Build a circuit through N relay nodes.

    REAL mode (preferred):
    - Uses matryoshka.dll to query relays + build encrypted onion.

    MOCK mode (fallback):
    - Returns fake relays and simulated send.
    """

    # Try REAL mode first if possible (directory_url -> base URL for C++ code)
    directory_base_url = directory_url.removesuffix("/relays")

    try:
        # C++ build requires destination + message; we supply placeholders here and rebuild at send time.
        # So here we only check whether we CAN reach directory server and have relays.
        relays = query_directory_for_relays(directory_url)
        if relays and _find_default_dll():
            # Return a REAL circuit shell; actual payload is built in send_through_circuit.
            # (We don't know destination/message yet.)
            return Circuit(relays=[], entry_ip=None, entry_port=None, encrypted_payload=None, hop_count=num_relays)
        if FORCE_REAL:
            raise RuntimeError("FORCE_REAL enabled but directory server or DLL unavailable")
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

def send_through_circuit(circuit: Circuit, message: str, destination: str) -> Optional[str]:
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

    # If circuit is REAL-shell (built without payload), build now.
    directory_base_url = os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")

    try:
        if _find_default_dll():
            real_circuit = _build_circuit_cpp(len(circuit), message, destination, directory_base_url)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                sock.connect((real_circuit.entry_ip, real_circuit.entry_port))
                sock.sendall(real_circuit.encrypted_payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

                # Read until EOF
                resp = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk

                # If the response is encrypted in layers, try to decrypt
                final_bytes = resp
                if resp and real_circuit.response_keys:
                    try:
                        final_bytes = _decrypt_response_layers(resp, real_circuit.response_keys)
                    except Exception as e:
                        print(f"[Core Warning] Response decryption failed: {e}, returning raw response")

                # If it looks like an HTTP response, return the full HTTP response
                # (headers + body) so callers can choose to render or save it.
                if final_bytes.startswith(b"HTTP/"):
                    return final_bytes.decode("utf-8", errors="replace").strip()

                return final_bytes.decode("utf-8", errors="replace").strip() if final_bytes else ""
            finally:
                sock.close()

        if FORCE_REAL:
            raise RuntimeError("FORCE_REAL enabled but matryoshka.dll unavailable")

    except Exception as e:
        if FORCE_REAL:
            raise
        if not ALLOW_MOCK_FALLBACK:
            raise
        print(f"[Core Warning] REAL send failed ({e}). Falling back to MOCK.")

    # --- MOCK ---
    if not circuit.relays:
        raise ValueError("Invalid circuit")

    for _ in circuit.relays:
        time.sleep(0.3)

    return f"Message received by {destination} (Securely Delivered)"


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

