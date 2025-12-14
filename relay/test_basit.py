#!/usr/bin/env python3
"""
Basit Test Scripti - Hızlı test için
"""

def test_imports():
    """Modüllerin import edilebilirliğini test eder"""
    print("=" * 60)
    print("MODÜL İMPORT TESTLERİ")
    print("=" * 60)
    
    # Test 1: core.cpp_wrapper
    try:
        from core.cpp_wrapper import get_wrapper, is_available
        print("✅ core.cpp_wrapper modülü başarıyla import edildi")
        
        available = is_available()
        if available:
            print("   ℹ️  C++ kütüphanesi MEVCUT (matryoshka.dll/libmatryoshka.so bulundu)")
        else:
            print("   ℹ️  C++ kütüphanesi BULUNAMADI (fallback mod kullanılacak)")
    except Exception as e:
        print(f"❌ core.cpp_wrapper hatası: {e}")
        return False
    
    # Test 2: core.crypto
    try:
        from core.crypto import decrypt_layer
        print("✅ core.crypto modülü başarıyla import edildi")
    except Exception as e:
        print(f"❌ core.crypto hatası: {e}")
        return False
    
    # Test 3: example_usage
    try:
        import example_usage
        print("✅ example_usage modülü başarıyla import edildi")
    except Exception as e:
        print(f"❌ example_usage hatası: {e}")
        return False
    
    # Test 4: relay_node
    try:
        import relay_node
        print("✅ relay_node modülü başarıyla import edildi")
    except Exception as e:
        print(f"❌ relay_node hatası: {e}")
        return False
    
    return True


def test_crypto_fallback():
    """Crypto modülünün fallback modunu test eder"""
    print("\n" + "=" * 60)
    print("CRYPTO FALLBACK MOD TESTİ")
    print("=" * 60)
    
    try:
        from core.crypto import decrypt_layer
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Test verisi: basit format (fallback mod için)
        test_data = b"127.0.0.1:8001|TestPayload123"
        print(f"Test verisi: {test_data}")
        
        # RSA anahtarı oluştur
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # decrypt_layer'ı çağır
        print("decrypt_layer() çağrılıyor...")
        next_hop, remaining_data = decrypt_layer(test_data, private_key)
        
        print(f"✅ Başarılı!")
        print(f"   Next hop: {next_hop}")
        print(f"   Remaining data: {remaining_data}")
        
        # Doğrulama
        if next_hop == "127.0.0.1:8001" and remaining_data == b"TestPayload123":
            print("✅ Sonuçlar doğru!")
            return True
        else:
            print("❌ Sonuçlar beklenenle eşleşmiyor!")
            return False
            
    except Exception as e:
        print(f"❌ Hata: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Ana test fonksiyonu"""
    print("\n🔍 BASİT TEST BAŞLIYOR...\n")
    
    results = []
    
    # Test 1: Import'lar
    results.append(("Modül Import'ları", test_imports()))
    
    # Test 2: Crypto fallback
    results.append(("Crypto Fallback Mod", test_crypto_fallback()))
    
    # Sonuçları özetle
    print("\n" + "=" * 60)
    print("TEST SONUÇLARI")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ BAŞARILI" if result else "❌ BAŞARISIZ"
        print(f"{test_name:.<40} {status}")
    
    print("=" * 60)
    print(f"Toplam: {passed}/{total} test başarılı")
    
    if passed == total:
        print("\n🎉 TÜM TESTLER BAŞARILI!")
    else:
        print(f"\n⚠️  {total - passed} test başarısız")


if __name__ == "__main__":
    main()

