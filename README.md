# Matryoshka

Tor benzeri (onion routing) anonim mesajlaşma ağı simülasyonu. Bir mesaj, bir dizi relay düğümünden oluşan bir "devre" üzerinden katman katman şifrelenerek hedefe iletilir.

## Mimari Özet

Sistem üç ana bileşenden oluşur:

```
┌─────────┐   ┌──────────────┐   ┌─────────┐
│ Client  │──▶│ Relay ...    │──▶│ Hedef   │
│ (cli/)  │   │ (relay/)     │   │         │
│         │◀──│              │◀──│         │
└─────────┘   └──────────────┘   └─────────┘
      │              │
      │ register/    │ register/
      │ heartbeat    │ heartbeat
      ▼              ▼
   ┌──────────────────────┐
   │ Directory Server      │
   │ (directory-server/)   │
   └──────────────────────┘
```

- **Client (`cli/`)** – Devre oluşturur, mesajı katman katman şifreler ve entry relay'e iletir.
- **Relay Node (`relay/`)** – Şifreli paketi alır, bir katmanı çözer ve bir sonraki hop'a iletir.
- **Directory Server (`directory-server/`)** – Relay'lerin kayıt olduğu, heartbeat ile aktif kalmasını sağlayan merkezi dizin.

Şifreleme çekirdeği (`cryptography/`) C++ ile yazılmıştır ve `dlls/` klasöründeki `Matryoshka.dll` üzerinden Python'a C ABI ile bağlanır.

## Klasör Yapısı

```
Matryoshka/
├── cli/                      # Client uygulaması (Python)
│   ├── client.py             # Ana client (interaktif + CLI modları)
│   └── core/
│       └── circuit_builder.py# Devre kurma ve mesaj gönderme
├── relay/                    # Relay node (Python)
│   ├── relay_node.py         # Relay TCP sunucusu
│   └── core/
│       ├── crypto.py         # Katman şifre çözme
│       └── cpp_wrapper.py    # C++ DLL wrapper
├── directory-server/         # Directory server (Node.js / Express)
│   └── directory_server.js
├── cryptography/             # C++ çekirdek kütüphanesi
│   ├── Matryoshka.cpp
│   └── matryoshka.h
├── dlls/                     # Derlenmiş DLL'ler ve yardımcı dosyalar
│   └── protocol.md           # Matryoshka protokol spesifikasyonu
└── scripts/                  # Başlatma / durdurma scriptleri
    ├── start.sh / start.ps1
    └── stop.sh / stop.ps1
```

> Bu repodaki `relay_node.py`, `test.py`, `e2e_test.py` ve `*.log` dosyaları kök dizinde dağınık kalmış eski dosyalardır; her bileşenin kendi klasöründeki güncel sürümleri kullanılır.

## Kurulum

### Gereksinimler

- Python 3.9+
- Node.js 18+ (directory server için)
- C++ derleyici + OpenSSL / cpr / Boost / nlohmann-json (kripto çekirdeğini derlemek için)

### Bağımlılıklar

```bash
# Python bileşenleri (cli/ ve relay/)
pip install -r cli/requirements.txt
pip install -r relay/requirements.txt

# Node.js directory server
cd directory-server && npm install
```

## Çalıştırma

### 1. Directory Server

```bash
cd directory-server
node directory_server.js
# Varsayılan port: 5000  (PORT ortam değişkeniyle değiştirilebilir)
```

### 2. Relay Node'ları (3 ayrı terminalde)

```bash
# relay/ klasöründen
python relay_node.py --id relay_1 --port 8001 --directory http://localhost:5000
python relay_node.py --id relay_2 --port 8002 --directory http://localhost:5000
python relay_node.py --id relay_3 --port 8003 --directory http://localhost:5000
```

Node'larla aynı portta çalışan hedef bir servis gerekir.

### 3. Client

```bash
# cli/ klasöründen
python client.py                                   # İnteraktif mod
python client.py -m "Merhaba" -d "192.168.1.1:8080" --directory http://localhost:5000
```

`MATRYOSHKA_DIRECTORY_URL` ortam değişkeni veya `--directory` bayrağı ile directory adresi belirtilebilir.

## Protokol

Paket formatı, hibrit (RSA-2048/OAEP + AES-256-CBC) şifreleme şemasına dayanır. Detaylı spesifikasyon için [dlls/protocol.md](dlls/protocol.md) dosyasına bakın.

## Notlar

- Bu proje bir **simülasyon/eğitim** amaçlıdır, production için uygun değildir.
- Directory server yoksa veya DLL bulunamazsa, client `ALLOW_MOCK_FALLBACK` sayesinde sahte relay'lerle simülasyon modunda çalışır.
