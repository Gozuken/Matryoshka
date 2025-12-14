#!/usr/bin/env python3
"""
Relay node'u test etmek için basit bir test scripti
"""

import socket
import time

def test_relay_connection(host='localhost', port=8001):
    """Relay node'a basit bir bağlantı testi yapar"""
    print(f"Relay node'a bağlanılıyor: {host}:{port}")
    
    try:
        # TCP bağlantısı kur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        sock.connect((host, port))
        print("✅ Bağlantı başarılı!")
        
        # Test verisi gönder (gerçek paket formatı değil, sadece bağlantı testi)
        test_data = b"Test packet data"
        sock.sendall(test_data)
        print(f"✅ Test verisi gönderildi: {len(test_data)} byte")
        
        # Kısa bir süre bekle
        time.sleep(0.5)
        
        sock.close()
        print("✅ Bağlantı kapatıldı")
        return True
        
    except ConnectionRefusedError:
        print(f"❌ Bağlantı reddedildi - Relay node çalışmıyor olabilir")
        return False
    except socket.timeout:
        print(f"❌ Bağlantı zaman aşımı")
        return False
    except Exception as e:
        print(f"❌ Hata: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Relay Node Test Scripti")
    print("=" * 50)
    print()
    print("NOT: Bu sadece bağlantı testidir.")
    print("Gerçek paket göndermek için decrypt_layer fonksiyonu implement edilmiş olmalı.")
    print()
    
    test_relay_connection()

