# Relay Node - Tor Benzeri Ağ Düğümü

Bu proje, şifreli paketleri alan, bir katman şifresini çözen ve bir sonraki hop'a ileten bir relay node (aktarım düğümü) implementasyonudur.

## Özellikler

- ✅ TCP sunucu ile ağ bağlantıları dinleme
- ✅ Şifreli paket alma ve işleme
- ✅ Directory server'a otomatik kayıt
- ✅ RSA anahtar çifti yönetimi
- ✅ Paket iletme (forwarding)
- ✅ Hata yönetimi ve logging
- ✅ Graceful shutdown (SIGINT/SIGTERM desteği)
- ✅ İstatistik takibi

## Kurulum

1. Gerekli bağımlılıkları yükleyin:

```bash
pip install -r requirements.txt
```

## Kullanım

### Temel Kullanım

```bash
python relay_node.py --id relay_1 --port 8001
```

### Tüm Parametreler

```bash
python relay_node.py \
    --id relay_1 \
    --port 8001 \
    --directory http://localhost:5000 \
    --private-key keys/relay_1_private.pem \
    --public-key keys/relay_1_public.pem
```

### Parametreler

- `--id`: Relay node'un benzersiz ID'si (zorunlu)
- `--port`: Dinlenecek TCP portu (varsayılan: 8001)
- `--directory`: Directory server URL'i (varsayılan: http://localhost:5000)
- `--private-key`: Özel anahtar dosya yolu (opsiyonel, yoksa otomatik oluşturulur)
- `--public-key`: Genel anahtar dosya yolu (opsiyonel, yoksa otomatik oluşturulur)

## Örnek Kullanım Senaryoları

### Senaryo 1: İlk Relay Node (Port 8001)

```bash
python relay_node.py --id relay_1 --port 8001
```

### Senaryo 2: İkinci Relay Node (Port 8002)

```bash
python relay_node.py --id relay_2 --port 8002
```

### Senaryo 3: Üçüncü Relay Node (Port 8003)

```bash
python relay_node.py --id relay_3 --port 8003
```

## Çalışma Prensibi

1. **Başlatma**: Relay node başlatıldığında:
   - RSA anahtar çifti oluşturulur veya yüklenir
   - Directory server'a kayıt olunur
   - TCP sunucusu belirtilen portta dinlemeye başlar

2. **Paket Alma**: Bir önceki hop'tan şifreli paket alınır

3. **Şifre Çözme**: `decrypt_layer()` fonksiyonu kullanılarak bir katman şifresi çözülür
   - Bir sonraki hop adresi çıkarılır
   - Kalan şifreli veri hazırlanır

4. **İletme**: Paket bir sonraki hop'a TCP üzerinden iletilir

5. **Bağlantı Kapatma**: İletim sonrası bağlantı temiz bir şekilde kapatılır

## Directory Server Entegrasyonu

Relay node başlatıldığında otomatik olarak directory server'a kayıt olur:

```json
POST http://directory:5000/register
{
  "id": "relay_1",
  "ip": "192.168.1.5",
  "port": 8001,
  "public_key": "<PEM_formatında_public_key>"
}
```

## Crypto Modülü

`core/crypto.py` dosyasındaki `decrypt_layer()` fonksiyonu proje lideri tarafından sağlanacaktır. Şu an için placeholder bir implementasyon mevcuttur.

### Beklenen Fonksiyon İmzası

```python
def decrypt_layer(encrypted_data: bytes, private_key: RSAPrivateKey) -> Tuple[str, bytes]:
    """
    Şifreli paketin bir katmanını çözer.
    
    Returns:
        (next_hop, remaining_data) tuple'ı
        - next_hop: "IP:PORT" formatında string
        - remaining_data: Hala şifreli bytes verisi
    """
    pass
```

## Logging

Tüm işlemler `relay_node.log` dosyasına ve konsola yazılır. Log seviyesi INFO'dur.

## İstatistikler

Relay node kapatıldığında şu istatistikler gösterilir:
- Alınan paket sayısı
- İletilen paket sayısı
- Hata sayısı
- Çalışma süresi

## Hata Yönetimi

- Bağlantı hataları yakalanır ve loglanır
- Timeout'lar yönetilir (10 saniye forwarding, 30 saniye receiving)
- Directory server bağlantı hataları yakalanır (node yine de çalışmaya devam eder)

## Güvenli Kapatma

Relay node, SIGINT (Ctrl+C) veya SIGTERM sinyalleri ile güvenli bir şekilde kapatılabilir:
- Aktif bağlantılar kapatılır
- İstatistikler gösterilir
- Log kayıtları tamamlanır

## Test Checklist

- [x] Relay başlatılır ve belirtilen portta dinler
- [x] Directory server'a başarıyla kayıt olur
- [x] Gelen TCP bağlantılarını kabul eder
- [x] Paket verilerini alabilir
- [x] Paketleri başka bir adrese iletebilir
- [x] Temel bağlantı hatalarını yönetir

## Gelecek Geliştirmeler (Opsiyonel)

- [ ] Heartbeat mekanizması (directory server'a periyodik sinyal)
- [ ] Bağlantı havuzu (sık kullanılan hop'lar için)
- [ ] Detaylı istatistikler ve izleme
- [ ] Multi-threading desteği
- [ ] Rate limiting
- [ ] Health check endpoint (HTTP)
- [ ] Yapılandırma dosyası desteği

## Lisans

Bu proje eğitim amaçlıdır.

