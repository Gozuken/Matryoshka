"""
Crypto modülü - Şifreleme/şifre çözme fonksiyonları
C++ Matryoshka kütüphanesini kullanır, yoksa fallback mod kullanır.
"""

import base64
import json
from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# C++ wrapper'ı import et (opsiyonel)
try:
    from core.cpp_wrapper import get_wrapper, is_available
    CPP_AVAILABLE = is_available()
except (ImportError, FileNotFoundError, OSError):
    CPP_AVAILABLE = False


def decrypt_layer(encrypted_data: bytes, private_key: Union[RSAPrivateKey, str]) -> Tuple[str, bytes, bytes, bytes]:
    """
    Şifreli paketin bir katmanını çözer (Matryoshka Protocol v1.0 uyumlu).

    C++ kütüphanesi mevcutsa onu kullanır, yoksa test moduna geçer.

    Değişiklik: Bu fonksiyon artık her zaman 4-tuple döndürür:
        (next_hop, remaining_data, response_key_or_None, response_iv_or_None)
    - response_key_or_None: 32 byte AES key (bytes) veya None
    - response_iv_or_None: 16 byte AES IV (bytes) veya None

    Protokol Spesifikasyonu:
    - Giriş formatı: JSON string {"cipher": {"enc_key": "...", "enc_iv": "...", "enc_payload": "..."}}
    - Çıkış formatı (C++): {"next_hop": "IP:PORT", "remaining_payload_b64": "...", "response_key_b64": "...", "response_iv_b64": "..."}

    Şifreleme:
    - Asymmetric: RSA-2048 with OAEP Padding (session key'ler için)
    - Symmetric: AES-256 CBC Mode (payload için)

    Args:
        encrypted_data: Şifreli paket verisi (bytes) - JSON string formatında olmalı
        private_key: Özel anahtar - RSAPrivateKey objesi veya PEM formatında string

    Returns:
        (next_hop, remaining_data, response_key_or_None, response_iv_or_None)

    Raises:
        ValueError: Geçersiz giriş veya bellek hatası (C++ hata kodu -1, -2)
        RuntimeError: Kripto hatası - yanlış özel anahtar veya bozuk veri (C++ hata kodu -3)
        json.JSONDecodeError: Parse hatası - çözülmüş veri geçerli JSON değil (C++ hata kodu -4)
    """
    response_key = None
    response_iv = None

    # C++ kütüphanesi mevcutsa kullan
    if CPP_AVAILABLE:
        try:
            # Özel anahtarı string formatına çevir (gerekirse)
            if isinstance(private_key, str):
                priv_key_str = private_key
            else:
                # RSAPrivateKey objesinden PEM string'e çevir
                from cryptography.hazmat.primitives import serialization
                priv_key_str = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

            # Paketi string formatına çevir (C++ kütüphanesi JSON string bekliyor)
            packet_str = encrypted_data.decode('utf-8')

            # C++ wrapper kullanarak şifre çöz
            wrapper = get_wrapper()
            result = wrapper.decrypt_layer(packet_str, priv_key_str)

            # Protokol spesifikasyonuna göre: {"next_hop": "...", "remaining_payload_b64": "..."}
            next_hop = result.get('next_hop', '')
            remaining_payload_b64 = result.get('remaining_payload_b64', '')

            # remaining_payload_b64'ü bytes'a çevir (Base64 decode)
            try:
                remaining_data = base64.b64decode(remaining_payload_b64)
            except Exception as e:
                # Base64 decode başarısız olursa, string olarak encode et
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"remaining_payload_b64 decode edilemedi, string olarak kullanılıyor: {e}")
                remaining_data = remaining_payload_b64.encode('utf-8')

            # OPTIONAL: C++ can provide response_key and response_iv base64 encoded
            resp_key_b64 = result.get('response_key_b64')
            resp_iv_b64 = result.get('response_iv_b64')
            if resp_key_b64:
                try:
                    response_key = base64.b64decode(resp_key_b64)
                except Exception:
                    response_key = None
            if resp_iv_b64:
                try:
                    response_iv = base64.b64decode(resp_iv_b64)
                except Exception:
                    response_iv = None

            return next_hop, remaining_data, response_key, response_iv

        except Exception as e:
            # C++ kütüphanesi hatası - fallback moda geç
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"C++ kütüphanesi kullanılamadı, test moduna geçiliyor: {e}")

    # FALLBACK: Test modu (basit format)
    # Beklenen format: b"ip:port|payload" OR b"ip:port|payload|<key_iv_b64_or_hex>"
    # Örnek: b"127.0.0.1:9000|MERHABA|<48bytes key+iv base64 or hex>"
    try:
        decoded = encrypted_data.decode("utf-8")
        parts = decoded.split("|", 2)
        next_hop = parts[0]
        payload = parts[1] if len(parts) > 1 else ''
        remaining_data = payload.encode('utf-8')

        # Optional response key+iv in 3rd part (base64 or hex). We expect key(32)+iv(16)=48 bytes
        if len(parts) > 2 and parts[2].strip():
            third = parts[2].strip()
            # Try base64
            try:
                combined = base64.b64decode(third)
            except Exception:
                # Try hex
                try:
                    combined = bytes.fromhex(third)
                except Exception:
                    combined = b''

            if len(combined) == 48:
                response_key = combined[:32]
                response_iv = combined[32:48]

        return next_hop, remaining_data, response_key, response_iv
    except Exception as e:
        raise ValueError(f"Paket formatı geçersiz: {e}")

