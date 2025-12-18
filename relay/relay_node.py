#!/usr/bin/env python3
"""
Relay Node - Tor benzeri ağ düğümü
Şifreli paketleri alır, bir katman şifresini çözer ve bir sonraki hop'a iletir.
"""

import socket
import json
import argparse
import sys
import logging
import signal
import time
from typing import Optional, Tuple
from pathlib import Path
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Core modülünden decrypt_layer fonksiyonunu import et
try:
    from core.crypto import decrypt_layer
except ImportError:
    # Fallback: Eğer core.crypto henüz yoksa basit bir placeholder kullan
    logging.warning("core.crypto modülü bulunamadı, placeholder kullanılıyor")
    def decrypt_layer(encrypted_data: bytes, private_key) -> Tuple[str, bytes]:
        """Placeholder decrypt_layer fonksiyonu"""
        # Bu fonksiyon proje lideri tarafından sağlanacak
        raise NotImplementedError("decrypt_layer fonksiyonu henüz implement edilmedi")

# Logging yapılandırması
# Ensure stdout/stderr use UTF-8 so non-ASCII log messages work on Windows consoles
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Configure logging: write log file in UTF-8 and stream to stdout
file_handler = logging.FileHandler('relay_node.log', encoding='utf-8')
stream_handler = logging.StreamHandler(sys.stdout)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[file_handler, stream_handler],
)
logger = logging.getLogger(__name__)


class RelayNode:
    """Relay node sınıfı - şifreli paketleri alır ve iletir"""
    
    def __init__(
        self,
        relay_id: str,
        port: int,
        directory_url: str = "http://localhost:5000",
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        advertise_ip: Optional[str] = None,
    ):
        """
        Relay node'u başlatır
        
        Args:
            relay_id: Relay node'un benzersiz ID'si
            port: Dinlenecek TCP portu
            directory_url: Directory server URL'i
            private_key_path: Özel anahtar dosya yolu (opsiyonel)
            public_key_path: Genel anahtar dosya yolu (opsiyonel)
        """
        self.relay_id = relay_id
        self.port = port
        self.directory_url = directory_url
        self.advertise_ip = advertise_ip
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.stats = {
            'packets_received': 0,
            'packets_forwarded': 0,
            'errors': 0,
            'start_time': time.time()
        }
        
        # RSA anahtar çiftini yükle veya oluştur
        self.private_key, self.public_key = self._load_or_generate_keys(
            private_key_path, public_key_path
        )
        
        # Sinyal işleyicileri
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_or_generate_keys(self, private_key_path: Optional[str], 
                               public_key_path: Optional[str]) -> Tuple:
        """RSA anahtar çiftini yükler veya yeni oluşturur"""
        if private_key_path and Path(private_key_path).exists():
            # Mevcut anahtarları yükle
            logger.info(f"Özel anahtar yükleniyor: {private_key_path}")
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            if public_key_path and Path(public_key_path).exists():
                with open(public_key_path, 'rb') as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
            else:
                public_key = private_key.public_key()
            
            return private_key, public_key
        else:
            # Yeni anahtar çifti oluştur
            logger.info("Yeni RSA anahtar çifti oluşturuluyor...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Anahtarları kaydet
            if private_key_path:
                self._save_key(private_key, private_key_path, is_private=True)
            if public_key_path:
                self._save_key(public_key, public_key_path, is_private=False)
            
            return private_key, public_key
    
    def _save_key(self, key, filepath: str, is_private: bool):
        """Anahtarı dosyaya kaydeder"""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        if is_private:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        with open(filepath, 'wb') as f:
            f.write(pem)
        logger.info(f"Anahtar kaydedildi: {filepath}")
    
    def get_public_key_pem(self) -> str:
        """Genel anahtarı PEM formatında string olarak döndürür"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def register_with_directory(self) -> bool:
        """Directory server'a kayıt olur"""
        try:
            # Kendi IP adresini al
            if getattr(self, "advertise_ip", None):
                local_ip = self.advertise_ip
            else:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)

                # Alternatif: Dış IP'yi almak için basit bir yöntem
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass
            
            registration_data = {
                "id": self.relay_id,
                "ip": local_ip,
                "port": self.port,
                "public_key": self.get_public_key_pem()
            }
            
            logger.info(f"Directory server'a kayıt olunuyor: {self.directory_url}/register")
            logger.debug(f"Kayıt verisi: {json.dumps(registration_data, indent=2)}")
            
            response = requests.post(
                f"{self.directory_url}/register",
                json=registration_data,
                timeout=10
            )
            
            if response.status_code in (200, 201):
                logger.info("Directory server'a başarıyla kayıt olundu")
                return True
            else:
                logger.error(f"Kayıt başarısız: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Directory server'a bağlanılamadı: {e}")
            return False
        except Exception as e:
            logger.error(f"Kayıt sırasında hata: {e}")
            return False
    
    def forward_packet(self, address: str, data: bytes) -> Optional[bytes]:
        """Paketi bir sonraki hop'a iletir ve varsa cevabı geri okur.

        Args:
            address: "IP:PORT" formatında hedef adres
            data: İletilecek veri (hala şifreli)

        Returns:
            - next hop'tan gelen response bytes (varsa)
            - hata durumunda None
        """
        try:
            # Adresi parse et
            if ':' not in address:
                logger.error(f"Geçersiz adres formatı: {address}")
                return None
            
            ip, port_str = address.rsplit(':', 1)
            port = int(port_str)
            
            logger.info(f"Paket iletililiyor: {ip}:{port}")
            
            forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            forward_socket.settimeout(10)  # 10 saniye timeout
            
            try:
                forward_socket.connect((ip, port))
                forward_socket.sendall(data)

                # Gönderim tamamlandı (half-close) -> karşı tarafın EOF alması için
                try:
                    forward_socket.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

                # Response oku (newline veya EOF'a kadar)
                response = b""
                while True:
                    chunk = forward_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\n" in response:
                        break

                logger.info(f"Paket başarıyla iletildi: {ip}:{port}")
                self.stats['packets_forwarded'] += 1
                return response if response else b""
            finally:
                forward_socket.close()
                
        except socket.timeout:
            logger.error(f"Bağlantı zaman aşımı: {address}")
            self.stats['errors'] += 1
            return None
        except socket.error as e:
            logger.error(f"Bağlantı hatası: {address} - {e}")
            self.stats['errors'] += 1
            return None
        except Exception as e:
            logger.error(f"İletim hatası: {e}")
            self.stats['errors'] += 1
            return None
    
    def handle_connection(self, connection: socket.socket, address: Tuple[str, int]):
        """Gelen bağlantıyı işler ve paketi işler"""
        logger.info(f"Yeni bağlantı: {address[0]}:{address[1]}")
        
        try:
            # Paket verisini al
            received_data = b''
            connection.settimeout(30)  # 30 saniye timeout
            
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                received_data += chunk
            
            if not received_data:
                logger.warning("Boş paket alındı")
                return
            
            logger.info(f"Paket alındı: {len(received_data)} byte")
            self.stats['packets_received'] += 1
            
            # Bir katman şifresini çöz
            try:
                next_hop, remaining_data = decrypt_layer(received_data, self.private_key)
                logger.info(f"Şifre çözüldü, bir sonraki hop: {next_hop}")
            except NotImplementedError:
                logger.error("decrypt_layer fonksiyonu henüz implement edilmedi")
                self.stats['errors'] += 1
                return
            except Exception as e:
                logger.error(f"Şifre çözme hatası: {e}")
                self.stats['errors'] += 1
                return
            
            # Paketi bir sonraki hop'a ilet + response oku
            response = self.forward_packet(next_hop, remaining_data)
            if response is None:
                logger.error(f"Paket iletilemedi: {next_hop}")
                return

            # Response varsa upstream'e geri gönder
            if response:
                try:
                    connection.sendall(response)
                except Exception as e:
                    logger.error(f"Response upstream'e gönderilemedi: {e}")
                    self.stats['errors'] += 1
            
        except socket.timeout:
            logger.warning(f"Bağlantı zaman aşımı: {address}")
        except Exception as e:
            logger.error(f"Bağlantı işleme hatası: {e}")
            self.stats['errors'] += 1
        finally:
            connection.close()
            logger.info(f"Bağlantı kapatıldı: {address[0]}:{address[1]}")
    
    def start_relay(self):
        """TCP sunucusunu başlatır ve bağlantıları dinler"""
        # Directory server'a kayıt ol
        if not self.register_with_directory():
            logger.warning("Directory server'a kayıt olunamadı, yine de devam ediliyor...")
        
        # TCP sunucusunu başlat
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(10)
            self.running = True
            
            logger.info(f"Relay node başlatıldı: {self.relay_id} - Port: {self.port}")
            logger.info("Bağlantılar dinleniyor...")
            
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)  # 1 saniye timeout (sinyal kontrolü için)
                    connection, address = self.server_socket.accept()
                    self.handle_connection(connection, address)
                except socket.timeout:
                    # Timeout normal, döngü devam eder
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Sunucu hatası: {e}")
                    
        except OSError as e:
            logger.error(f"Port {self.port} kullanılamıyor: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Sunucu başlatma hatası: {e}")
            sys.exit(1)
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Relay node'u güvenli bir şekilde kapatır"""
        if not self.running:
            return
        
        logger.info("Relay node kapatılıyor...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # İstatistikleri göster
        uptime = time.time() - self.stats['start_time']
        logger.info("=" * 50)
        logger.info("Relay Node İstatistikleri:")
        logger.info(f"  Alınan paketler: {self.stats['packets_received']}")
        logger.info(f"  İletilen paketler: {self.stats['packets_forwarded']}")
        logger.info(f"  Hatalar: {self.stats['errors']}")
        logger.info(f"  Çalışma süresi: {uptime:.2f} saniye")
        logger.info("=" * 50)
    
    def _signal_handler(self, signum, frame):
        """Sinyal işleyici (SIGINT, SIGTERM)"""
        logger.info(f"Sinyal alındı: {signum}")
        self.shutdown()
        sys.exit(0)


def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(description='Relay Node - Tor benzeri ağ düğümü')
    parser.add_argument('--id', type=str, required=True, help='Relay node ID (örn: relay_1)')
    parser.add_argument('--port', type=int, default=8001, help='Dinlenecek TCP portu (varsayılan: 8001)')
    parser.add_argument('--directory', type=str, default='http://localhost:5000',
                       help='Directory server URL (varsayılan: http://localhost:5000)')
    parser.add_argument('--ip', type=str, help='Directory servera register edilirken kullanılacak IP (opsiyonel)')
    parser.add_argument('--private-key', type=str, help='Özel anahtar dosya yolu')
    parser.add_argument('--public-key', type=str, help='Genel anahtar dosya yolu')
    
    args = parser.parse_args()
    
    # Relay node'u oluştur ve başlat
    relay = RelayNode(
        relay_id=args.id,
        port=args.port,
        directory_url=args.directory,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        advertise_ip=args.ip,
    )
    
    try:
        relay.start_relay()
    except KeyboardInterrupt:
        logger.info("Kullanıcı tarafından durduruldu")
        relay.shutdown()


if __name__ == '__main__':
    main()

