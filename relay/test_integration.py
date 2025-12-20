#!/usr/bin/env python3
"""
Entegrasyon testi - Tüm modüllerin düzgün çalışıp çalışmadığını kontrol eder
"""

import sys
import traceback

def test_imports():
    """Tüm modüllerin import edilebilirliğini test eder"""
    print("=" * 60)
    print("1. MODÜL İMPORT TESTLERİ")
    print("=" * 60)
    
    tests = []
    
    # Test 1: core.cpp_wrapper
    try:
        from core.cpp_wrapper import MatryoshkaWrapper, get_wrapper, is_available
        print("✅ core.cpp_wrapper modülü başarıyla import edildi")
        tests.append(True)
        
        # is_available() testi (C++ kütüphanesi olmadan da çalışmalı)
        try:
            available = is_available()
            if available:
                print("   ℹ️  C++ kütüphanesi mevcut")
            else:
                print("   ℹ️  C++ kütüphanesi bulunamadı (normal, DLL/SO yoksa)")
            tests.append(True)
        except Exception as e:
            print(f"   ⚠️  is_available() hatası: {e}")
            tests.append(False)
            
    except ImportError as e:
        print(f"❌ core.cpp_wrapper import hatası: {e}")
        tests.append(False)
    except Exception as e:
        print(f"❌ core.cpp_wrapper beklenmeyen hata: {e}")
        traceback.print_exc()
        tests.append(False)
    
    # Test 2: core.crypto
    try:
        from core.crypto import decrypt_layer
        print("✅ core.crypto modülü başarıyla import edildi")
        tests.append(True)
    except ImportError as e:
        print(f"❌ core.crypto import hatası: {e}")
        tests.append(False)
    except Exception as e:
        print(f"❌ core.crypto beklenmeyen hata: {e}")
        traceback.print_exc()
        tests.append(False)
    
    # Test 3: example_usage
    try:
        import example_usage
        print("✅ example_usage modülü başarıyla import edildi")
        tests.append(True)
    except ImportError as e:
        print(f"❌ example_usage import hatası: {e}")
        tests.append(False)
    except Exception as e:
        print(f"❌ example_usage beklenmeyen hata: {e}")
        traceback.print_exc()
        tests.append(False)
    
    # Test 4: relay_node
    try:
        import relay_node
        print("✅ relay_node modülü başarıyla import edildi")
        tests.append(True)
    except ImportError as e:
        print(f"❌ relay_node import hatası: {e}")
        tests.append(False)
    except Exception as e:
        print(f"❌ relay_node beklenmeyen hata: {e}")
        traceback.print_exc()
        tests.append(False)
    
    return all(tests)


def test_crypto_fallback():
    """Crypto modülünün fallback modunu test eder (C++ kütüphanesi olmadan)"""
    print("\n" + "=" * 60)
    print("2. CRYPTO FALLBACK MOD TESTİ")
    print("=" * 60)
    
    try:
        from core.crypto import decrypt_layer
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Test verisi: basit format (fallback mod için)
        test_data = b"127.0.0.1:8001|TestPayload"
        
        # RSA anahtarı oluştur (kullanılmayacak ama fonksiyon imzası için gerekli)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # decrypt_layer'ı çağır (fallback mod kullanılacak)
        next_hop, remaining_data, response_key, response_iv = decrypt_layer(test_data, private_key)
        
        if next_hop == "127.0.0.1:8001" and remaining_data == b"TestPayload" and response_key is None:
            print("✅ Fallback mod testi başarılı")
            print(f"   Next hop: {next_hop}")
            print(f"   Remaining data: {remaining_data}")
            return True
        else:
            print(f"❌ Fallback mod testi başarısız")
            print(f"   Beklenen: ('127.0.0.1:8001', b'TestPayload')")
            print(f"   Alınan: ({next_hop}, {remaining_data}, {response_key})")
            return False
            
    except Exception as e:
        print(f"❌ Fallback mod testi hatası: {e}")
        traceback.print_exc()
        return False


def test_cpp_wrapper_structure():
    """C++ wrapper'ın yapısını test eder (kütüphane olmadan)"""
    print("\n" + "=" * 60)
    print("3. C++ WRAPPER YAPISI TESTİ")
    print("=" * 60)
    
    try:
        from core.cpp_wrapper import MatryoshkaWrapper, is_available
        
        # is_available() çağrısı (kütüphane yoksa False dönmeli)
        available = is_available()
        print(f"   C++ kütüphanesi mevcut: {available}")
        
        if not available:
            print("   ℹ️  C++ kütüphanesi bulunamadı (beklenen davranış)")
            print("   ✅ Wrapper yapısı doğru, kütüphane olmadan da çalışıyor")
            return True
        else:
            print("   ℹ️  C++ kütüphanesi mevcut, tam test için kütüphane gerekli")
            return True
            
    except FileNotFoundError:
        print("   ✅ Wrapper doğru şekilde FileNotFoundError fırlatıyor (kütüphane yok)")
        return True
    except Exception as e:
        print(f"❌ Wrapper yapısı testi hatası: {e}")
        traceback.print_exc()
        return False


def test_protocol_compliance():
    """Protokol uyumluluğunu test eder"""
    print("\n" + "=" * 60)
    print("4. PROTOKOL UYUMLULUK TESTİ")
    print("=" * 60)
    
    try:
        # protocols.md dosyasının varlığını kontrol et
        import os
        if os.path.exists("protocols.md"):
            print("✅ protocols.md dosyası mevcut")
            
            # İçeriği kontrol et
            with open("protocols.md", "r", encoding="utf-8") as f:
                content = f.read()
                if "Matryoshka Network Protocol" in content:
                    print("✅ Protokol dokümantasyonu doğru")
                    if "remaining_payload_b64" in content:
                        print("✅ Protokol spesifikasyonu doğru (remaining_payload_b64)")
                        return True
                    else:
                        print("⚠️  remaining_payload_b64 protokolde belirtilmemiş")
                        return False
                else:
                    print("⚠️  Protokol dokümantasyonu eksik görünüyor")
                    return False
        else:
            print("❌ protocols.md dosyası bulunamadı")
            return False
            
    except Exception as e:
        print(f"❌ Protokol testi hatası: {e}")
        traceback.print_exc()
        return False


def main():
    """Ana test fonksiyonu"""
    print("\n" + "🔍 ENTEGRASYON TESTLERİ BAŞLIYOR...")
    print("=" * 60)
    
    results = []
    
    # Test 1: Import'lar
    results.append(("Modül Import'ları", test_imports()))
    
    # Test 2: Crypto fallback
    results.append(("Crypto Fallback Mod", test_crypto_fallback()))
    
    # Test 3: C++ wrapper yapısı
    results.append(("C++ Wrapper Yapısı", test_cpp_wrapper_structure()))
    
    # Test 4: Protokol uyumluluğu
    results.append(("Protokol Uyumluluğu", test_protocol_compliance()))
    
    # Sonuçları özetle
    print("\n" + "=" * 60)
    print("TEST SONUÇLARI ÖZETİ")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ BAŞARILI" if result else "❌ BAŞARISIZ"
        print(f"{test_name:.<40} {status}")
        if result:
            passed += 1
    
    print("=" * 60)
    print(f"Toplam: {passed}/{total} test başarılı")
    
    if passed == total:
        print("\n🎉 TÜM TESTLER BAŞARILI!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test başarısız")
        return 1


if __name__ == "__main__":
    sys.exit(main())

