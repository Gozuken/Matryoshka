#!/usr/bin/env python3
"""
Basit test scripti - Projenin çalışıp çalışmadığını kontrol eder
"""

import sys

def test_imports():
    """Modül importlarını test et"""
    print("1. Modül importlarını kontrol ediliyor...")
    try:
        from core.circuit_builder import build_circuit, send_through_circuit, Circuit
        print("   ✓ Modül importları başarılı")
        return True
    except ImportError as e:
        print(f"   ✗ Modül import hatası: {e}")
        return False

def test_circuit_building():
    """Circuit oluşturmayı test et"""
    print("\n2. Circuit oluşturma test ediliyor...")
    try:
        from core.circuit_builder import build_circuit
        circuit = build_circuit(num_relays=3)
        print(f"   ✓ Circuit başarıyla oluşturuldu: {circuit}")
        return True
    except Exception as e:
        print(f"   ✗ Circuit oluşturma hatası: {e}")
        return False

def test_message_sending():
    """Mesaj göndermeyi test et"""
    print("\n3. Mesaj gönderme test ediliyor...")
    try:
        from core.circuit_builder import build_circuit, send_through_circuit
        circuit = build_circuit(num_relays=3)
        result = send_through_circuit(circuit, "Test mesajı", "192.168.1.1:8080")
        print(f"   ✓ Mesaj başarıyla gönderildi: {result}")
        return True
    except Exception as e:
        print(f"   ✗ Mesaj gönderme hatası: {e}")
        return False

def test_client_import():
    """Client modülünü test et"""
    print("\n4. Client modülü kontrol ediliyor...")
    try:
        import client
        print("   ✓ Client modülü başarıyla yüklendi")
        return True
    except Exception as e:
        print(f"   ✗ Client modülü hatası: {e}")
        return False

def main():
    print("=" * 50)
    print("Matryoshka Anonymous Messenger - Test Scripti")
    print("=" * 50)
    
    results = []
    
    results.append(test_imports())
    results.append(test_circuit_building())
    results.append(test_message_sending())
    results.append(test_client_import())
    
    print("\n" + "=" * 50)
    print("Test Sonuçları:")
    print("=" * 50)
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"✓ Tüm testler başarılı! ({passed}/{total})")
        print("\nProje çalışıyor! Şimdi şu komutla çalıştırabilirsiniz:")
        print("  python client.py")
        return 0
    else:
        print(f"✗ Bazı testler başarısız ({passed}/{total})")
        print("\nLütfen hataları kontrol edin.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

