# Matryoshka Anonymous Messenger

Anonim mesajlaşma sistemi - Onion Routing (Soğan Yönlendirme) simülasyonu

## Kurulum

1. Gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

## Projeyi Test Etme

### Yöntem 1: Test Scripti ile (Önerilen)

Projenin çalışıp çalışmadığını kontrol etmek için test scriptini çalıştırın:

```bash
python test.py
```

Bu script şunları kontrol eder:
- ✓ Modül importları
- ✓ Circuit oluşturma
- ✓ Mesaj gönderme
- ✓ Client modülü

### Yöntem 2: Client'ı Doğrudan Çalıştırma

#### İnteraktif Mod (Önerilen)
```bash
python client.py
```

Program sizden mesaj ve hedef adres isteyecektir.

#### Komut Satırı Modu
```bash
python client.py --message "Merhaba Dünya" --dest "192.168.1.1:8080"
```

Verbose mod için:
```bash
python client.py --message "Test" --dest "10.0.0.1:5000" --verbose
```

### Yöntem 3: Python'da Manuel Test

Python REPL'de test edebilirsiniz:

```python
# Python'u başlatın
python

# Sonra şu komutları çalıştırın:
from core.circuit_builder import build_circuit, send_through_circuit

# Circuit oluştur
circuit = build_circuit(num_relays=3)
print(f"Circuit oluşturuldu: {circuit}")

# Mesaj gönder
result = send_through_circuit(circuit, "Test mesajı", "192.168.1.1:8080")
print(f"Sonuç: {result}")
```

## Başarılı Çalışma Belirtileri

Proje düzgün çalışıyorsa şunları görmelisiniz:

1. **Test scripti çalıştırıldığında:**
   ```
   ✓ Tüm testler başarılı! (4/4)
   ```

2. **Client çalıştırıldığında:**
   - Renkli başlık görünür
   - "Building circuit..." mesajı
   - "✓ Circuit established" mesajı
   - Mock relay'ler kullanılıyorsa "[Core Warning] Directory server unreachable" uyarısı (normal)
   - Mesaj başarıyla gönderilir

3. **Hata durumunda:**
   - Kırmızı ✗ işaretli hata mesajları görünür
   - Import hatası varsa modül bulunamadı hatası verir

## Sorun Giderme

### Import Hatası
```
✗ Error: core.circuit_builder module not found
```
**Çözüm:** `core/` klasörünün ve `core/circuit_builder.py` dosyasının var olduğundan emin olun.

### requests Modülü Bulunamadı
```
ModuleNotFoundError: No module named 'requests'
```
**Çözüm:** `pip install requests` veya `pip install -r requirements.txt` çalıştırın.

### Directory Server Hatası
Mock fallback modu aktif olduğu için directory sunucusu olmasa bile proje çalışmalı. Eğer hata alıyorsanız `core/circuit_builder.py` dosyasında `ALLOW_MOCK_FALLBACK = True` olduğundan emin olun.

## Proje Yapısı

```
Matryoshka/
├── client.py              # Ana client uygulaması
├── core/
│   ├── __init__.py        # Paket dosyası
│   └── circuit_builder.py # Circuit oluşturma ve mesaj gönderme
├── test.py                # Test scripti
├── requirements.txt       # Python bağımlılıkları
└── README.md             # Bu dosya
```

## Özellikler

- ✅ Multi-hop circuit oluşturma
- ✅ Anonim mesaj gönderme simülasyonu
- ✅ Mock fallback modu (sunucu olmadan test)
- ✅ Renkli terminal çıktısı
- ✅ İnteraktif ve komut satırı modları
- ✅ Detaylı hata mesajları

## Notlar

- Bu proje bir simülasyondur ve gerçek ağ bağlantıları kullanmaz
- Mock modunda çalışırken gerçek sunuculara bağlanmaz
- Test amaçlıdır ve production için uygun değildir

