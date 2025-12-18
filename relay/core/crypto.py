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

    Returns:
        (next_hop, remaining_data, response_key, response_iv)
        - response_key: 32-byte AES key (bytes) or b'' if unavailable
        - response_iv: 16-byte IV (bytes) or b'' if unavailable
    """
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

            # Protokole göre: next_hop, remaining_payload_b64, and optional response_key_b64/response_iv_b64
            next_hop = result.get('next_hop', '')
            remaining_payload_b64 = result.get('remaining_payload_b64', '')
            response_key_b64 = result.get('response_key_b64')
            response_iv_b64 = result.get('response_iv_b64')

            # Decode remaining payload
            try:
                remaining_data = base64.b64decode(remaining_payload_b64)
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"remaining_payload_b64 decode edilemedi, string olarak kullanılıyor: {e}")
                remaining_data = remaining_payload_b64.encode('utf-8')

            # Decode optional response key/iv
            response_key = b''
            response_iv = b''
            if response_key_b64:
                try:
                    response_key = base64.b64decode(response_key_b64)
                except Exception:
                    response_key = b''
            if response_iv_b64:
                try:
                    response_iv = base64.b64decode(response_iv_b64)
                except Exception:
                    response_iv = b''

            return next_hop, remaining_data, response_key, response_iv

        except Exception as e:
            # C++ kütüphanesi hatası - fallback moda geç
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"C++ kütüphanesi kullanılamadı, test moduna geçiliyor: {e}")
    
    # FALLBACK: Test modu (basit format)
    # Beklenen format: b"ip:port|payload"
    # Örnek: b"127.0.0.1:9000|MERHABA"
    try:
        decoded = encrypted_data.decode("utf-8")
        next_hop, payload = decoded.split("|", 1)
        # Fallback modunda response key/iv yok
        return next_hop, payload.encode("utf-8"), b"", b""
    except Exception as e:
        raise ValueError(f"Paket formatı geçersiz: {e}")

