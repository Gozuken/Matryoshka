# Nasıl Test Edilir? - Kullanım Kılavuzu

## 🚀 Hızlı Test (Önerilen)

### Yöntem 1: Basit Test Scripti
```bash
python test_basit.py
```

Bu script:
- ✅ Tüm modüllerin import edilebilirliğini kontrol eder
- ✅ Crypto fallback modunu test eder
- ✅ Hızlı sonuç verir

### Yöntem 2: Detaylı Test Scripti
```bash
python test_integration.py
```

Bu script daha detaylı testler yapar:
- ✅ Modül import'ları
- ✅ Crypto fallback modu
- ✅ C++ wrapper yapısı
- ✅ Protokol uyumluluğu

## 📝 Manuel Test Adımları

### Test 1: Modül Import'ları

Python konsolunu açın ve şunları deneyin:

```python
# Test 1: C++ Wrapper
from core.cpp_wrapper import get_wrapper, is_available
print("C++ kütüphanesi mevcut mu?", is_available())

# Test 2: Crypto Modülü
from core.crypto import decrypt_layer
print("decrypt_layer fonksiyonu yüklendi")

# Test 3: Example Usage
import example_usage
print("example_usage modülü yüklendi")

# Test 4: Relay Node
import relay_node
print("relay_node modülü yüklendi")
```

### Test 2: Crypto Fallback Modu

```python
from core.crypto import decrypt_layer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Test verisi oluştur
test_data = b"127.0.0.1:8001|TestMesaj"

# RSA anahtarı oluştur
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Şifre çözme testi
next_hop, remaining_data = decrypt_layer(test_data, private_key)

print(f"Next hop: {next_hop}")
print(f"Remaining data: {remaining_data}")

# Beklenen sonuç:
# Next hop: 127.0.0.1:8001
# Remaining data: b'TestMesaj'
```

### Test 3: Relay Node (C++ Kütüphanesi Olmadan)

```bash
# Terminal 1: Relay node'u başlat
python relay_node.py --id test_relay --port 8001

# Terminal 2: Test scripti çalıştır
python test_relay.py
```

### Test 4: Example Usage (C++ Kütüphanesi Gerekli)

```bash
# Önce matryoshka.dll (Windows) veya libmatryoshka.so (Linux) dosyasını
# proje dizinine ekleyin, sonra:

python example_usage.py
```

## 🔍 Ne Test Ediliyor?

### ✅ Başarılı Olması Gerekenler:

1. **Modül Import'ları**
   - Tüm modüller import edilebilmeli
   - Hata olmamalı

2. **Crypto Fallback Modu**
   - C++ kütüphanesi olmadan çalışmalı
   - Basit format (`ip:port|payload`) işlenebilmeli

3. **Protokol Uyumluluğu**
   - `remaining_payload_b64` alanı kullanılmalı
   - JSON formatları doğru olmalı

### ⚠️ Dikkat Edilmesi Gerekenler:

1. **C++ Kütüphanesi Yoksa:**
   - Sistem otomatik fallback moda geçer
   - Bu normal bir davranıştır
   - Test modu çalışır

2. **Directory Server:**
   - `example_usage.py` için directory server gerekli
   - Varsayılan: `http://localhost:5600`

## 🐛 Sorun Giderme

### Hata: "ModuleNotFoundError: No module named 'core'"
**Çözüm:** Proje dizininde olduğunuzdan emin olun:
```bash
cd C:\Users\Sıla\OneDrive\Desktop\network
python test_basit.py
```

### Hata: "C++ kütüphanesi bulunamadı"
**Çözüm:** Bu normal! Fallback mod çalışacak. C++ kütüphanesi eklemek isterseniz:
- Windows: `matryoshka.dll` dosyasını proje dizinine ekleyin
- Linux: `libmatryoshka.so` dosyasını proje dizinine ekleyin

### Hata: "ImportError: cannot import name 'decrypt_layer'"
**Çözüm:** `core/crypto.py` dosyasının mevcut olduğundan emin olun.

## 📊 Test Sonuçları

Test başarılı olursa şunu görmelisiniz:

```
🔍 BASİT TEST BAŞLIYOR...

============================================================
MODÜL İMPORT TESTLERİ
============================================================
✅ core.cpp_wrapper modülü başarıyla import edildi
   ℹ️  C++ kütüphanesi BULUNAMADI (fallback mod kullanılacak)
✅ core.crypto modülü başarıyla import edildi
✅ example_usage modülü başarıyla import edildi
✅ relay_node modülü başarıyla import edildi

============================================================
CRYPTO FALLBACK MOD TESTİ
============================================================
Test verisi: b'127.0.0.1:8001|TestPayload123'
decrypt_layer() çağrılıyor...
✅ Başarılı!
   Next hop: 127.0.0.1:8001
   Remaining data: b'TestPayload123'
✅ Sonuçlar doğru!

============================================================
TEST SONUÇLARI
============================================================
Modül Import'ları......................... ✅ BAŞARILI
Crypto Fallback Mod....................... ✅ BAŞARILI
============================================================
Toplam: 2/2 test başarılı

🎉 TÜM TESTLER BAŞARILI!
```

## 🎯 Sonraki Adımlar

Testler başarılı olduktan sonra:

1. **C++ Kütüphanesi Ekleme:**
   - `matryoshka.dll` veya `libmatryoshka.so` dosyasını ekleyin
   - Sistem otomatik olarak C++ kütüphanesini kullanacak

2. **Directory Server Kurulumu:**
   - `example_usage.py` için directory server gerekli
   - Server'ı başlatın ve test edin

3. **Relay Node Testi:**
   - Birden fazla relay node başlatın
   - Paket iletimini test edin

