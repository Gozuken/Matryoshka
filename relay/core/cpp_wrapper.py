"""
C++ Matryoshka kütüphanesi wrapper modülü
C++ DLL/SO dosyasını ctypes ile yükler ve Python'dan kullanılabilir hale getirir.
"""

import ctypes
import os
import json
from typing import Tuple, Dict, Optional


class MatryoshkaWrapper:
    """C++ Matryoshka kütüphanesi için Python wrapper sınıfı"""
    
    def __init__(self, dll_path: Optional[str] = None):
        """
        C++ kütüphanesini yükler
        
        Args:
            dll_path: DLL/SO dosyasının yolu. None ise varsayılan yollar denenir.
        """
        self.lib = None
        self.dll_path = dll_path or self._find_default_dll()
        
        if not self.dll_path:
            raise FileNotFoundError(
                "C++ kütüphanesi bulunamadı. "
                "Lütfen matryoshka.dll (Windows) veya libmatryoshka.so (Linux) dosyasını "
                "proje dizinine ekleyin."
            )
        
        try:
            dll_abs = os.path.abspath(self.dll_path)

            # Windows: bağımlı DLL'lerin (libcrypto, cpr, vb.) aynı klasörden bulunması için
            # arama yoluna ekle (Python 3.8+).
            if os.name == "nt":
                try:
                    os.add_dll_directory(os.path.dirname(dll_abs))
                except Exception:
                    pass

            self.lib = ctypes.CDLL(dll_abs)
            self._setup_function_signatures()
        except OSError as e:
            raise OSError(f"C++ kütüphanesi yüklenemedi: {e}")
    
    def _find_default_dll(self) -> Optional[str]:
        """Varsayılan DLL/SO dosyasını bulur.

        Arama sırası:
        1) MATRYOSHKA_DLL_PATH env var
        2) CWD
        3) Repo root ve /dlls klasörü (bu dosyanın konumuna göre)
        """
        env_path = os.environ.get("MATRYOSHKA_DLL_PATH")
        if env_path and os.path.exists(env_path):
            return env_path

        if os.name == 'nt':
            lib_filenames = ["matryoshka.dll", "Matryoshka.dll"]
        else:
            lib_filenames = ["libmatryoshka.so"]

        here = os.path.dirname(__file__)              # relay/core
        relay_dir = os.path.abspath(os.path.join(here, ".."))
        repo_root = os.path.abspath(os.path.join(here, "..", ".."))

        candidates: list[str] = []
        for name in lib_filenames:
            candidates.extend(
                [
                    os.path.join(os.getcwd(), name),
                    os.path.join(here, name),
                    os.path.join(relay_dir, name),
                    os.path.join(repo_root, name),
                    os.path.join(repo_root, "dlls", name),
                ]
            )

        for p in candidates:
            if os.path.exists(p):
                return p

        return None
    
    def _setup_function_signatures(self):
        """C++ fonksiyonlarının imzalarını tanımlar"""
        # Key generation
        self.lib.matryoshka_generate_keypair_c.argtypes = [
            ctypes.POINTER(ctypes.c_char_p), 
            ctypes.POINTER(ctypes.c_char_p)
        ]
        
        # Circuit building
        self.lib.matryoshka_build_circuit_json_c.argtypes = [
            ctypes.c_int,      # hops
            ctypes.c_char_p,   # message
            ctypes.c_int,      # message_len
            ctypes.c_char_p,   # destination
            ctypes.c_char_p,   # directory_url
            ctypes.POINTER(ctypes.c_char_p)  # output
        ]
        
        # Layer decryption
        self.lib.matryoshka_decrypt_layer_json_c.argtypes = [
            ctypes.c_char_p,   # packet_str
            ctypes.c_char_p,   # private_key
            ctypes.POINTER(ctypes.c_char_p)  # output
        ]
        
        # Memory cleanup
        self.lib.matryoshka_free_buffer.argtypes = [ctypes.c_void_p]
    
    def generate_keypair(self) -> Tuple[str, str]:
        """
        RSA anahtar çifti oluşturur (C++ kütüphanesi kullanarak)
        
        Returns:
            (private_key, public_key) tuple'ı - her ikisi de PEM formatında string
        """
        priv_ptr = ctypes.c_char_p()
        pub_ptr = ctypes.c_char_p()
        
        res = self.lib.matryoshka_generate_keypair_c(
            ctypes.byref(priv_ptr), 
            ctypes.byref(pub_ptr)
        )
        
        if res != 0:
            raise Exception("C++ kütüphanesinde anahtar oluşturma başarısız")
        
        priv = priv_ptr.value.decode('utf-8')
        pub = pub_ptr.value.decode('utf-8')
        
        # Belleği temizle
        self.lib.matryoshka_free_buffer(priv_ptr)
        self.lib.matryoshka_free_buffer(pub_ptr)
        
        return priv, pub
    
    def build_circuit(self, hops: int, message: str, destination: str, 
                     directory_url: str) -> Dict:
        """
        Şifreli devre (circuit) oluşturur
        
        Args:
            hops: Devre uzunluğu (kaç relay kullanılacak)
            message: Gönderilecek mesaj
            destination: Hedef adres (örn: "10.0.0.99:5600")
            directory_url: Directory server URL'i
        
        Returns:
            Circuit bilgilerini içeren dictionary
        """
        out_ptr = ctypes.c_char_p()
        
        res = self.lib.matryoshka_build_circuit_json_c(
            hops,
            message.encode('utf-8'),
            len(message),
            destination.encode('utf-8'),
            directory_url.encode('utf-8'),
            ctypes.byref(out_ptr)
        )
        
        if res != 0:
            raise Exception(f"Devre oluşturma başarısız (Hata kodu: {res})")
        
        json_str = out_ptr.value.decode('utf-8')
        self.lib.matryoshka_free_buffer(out_ptr)
        
        return json.loads(json_str)
    
    def decrypt_layer(self, packet_str: str, private_key: str) -> Dict:
        """
        Paketin bir katmanını çözer (Protokol v1.0 uyumlu)
        
        Protokol spesifikasyonuna göre:
        - Giriş: JSON string {"cipher": {"enc_key": "...", "enc_iv": "...", "enc_payload": "..."}}
        - Çıkış: JSON string {"next_hop": "...", "remaining_payload_b64": "..."}
        
        Args:
            packet_str: Şifreli paket (JSON string formatında)
            private_key: Özel anahtar (PEM formatında string)
        
        Returns:
            Çözülmüş katman bilgilerini içeren dictionary:
            {
                "next_hop": "IP:PORT",
                "remaining_payload_b64": "Base64 encoded blob"
            }
        
        Raises:
            ValueError: Hata kodu -1 veya -2 (Invalid Input / Memory Error)
            RuntimeError: Hata kodu -3 (Crypto Failure - Wrong Private Key or Corrupted Data)
            json.JSONDecodeError: Hata kodu -4 (Parse Error - Decrypted data was not valid JSON)
        """
        out_ptr = ctypes.c_char_p()
        
        res = self.lib.matryoshka_decrypt_layer_json_c(
            packet_str.encode('utf-8'),
            private_key.encode('utf-8'),
            ctypes.byref(out_ptr)
        )
        
        if res != 0:
            # Protokol spesifikasyonuna göre hata kodlarını işle
            if res == -1 or res == -2:
                raise ValueError(f"Geçersiz giriş veya bellek hatası (Hata kodu: {res})")
            elif res == -3:
                raise RuntimeError(f"Kripto hatası - Yanlış özel anahtar veya bozuk veri (Hata kodu: {res})")
            elif res == -4:
                # JSONDecodeError için doğru format: msg, doc, pos
                raise json.JSONDecodeError(
                    f"Parse hatası - Çözülmüş veri geçerli JSON değil (Hata kodu: {res})",
                    "", 0
                )
            else:
                raise Exception(f"Bilinmeyen hata kodu: {res}")
        
        json_str = out_ptr.value.decode('utf-8')
        self.lib.matryoshka_free_buffer(out_ptr)
        
        return json.loads(json_str)


# Global wrapper instance (lazy loading)
_wrapper_instance: Optional[MatryoshkaWrapper] = None


def get_wrapper(dll_path: Optional[str] = None) -> MatryoshkaWrapper:
    """
    Global wrapper instance'ı döndürür (singleton pattern)
    
    Args:
        dll_path: İlk çağrıda DLL yolu belirtilebilir
    
    Returns:
        MatryoshkaWrapper instance
    """
    global _wrapper_instance
    
    if _wrapper_instance is None:
        _wrapper_instance = MatryoshkaWrapper(dll_path)
    
    return _wrapper_instance


def is_available() -> bool:
    """C++ kütüphanesinin mevcut olup olmadığını kontrol eder"""
    try:
        get_wrapper()
        return True
    except (FileNotFoundError, OSError):
        return False

