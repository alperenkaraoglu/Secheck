> ⚠️ **Yasal Uyarı (Legal Disclaimer):** Secheck, yalnızca eğitim, güvenlik araştırmaları ve yetkili olunan sistemlerin güvenlik duruşunu denetlemek amacıyla geliştirilmiştir. İzinsiz sistemlerde aktif tarama modüllerinin kullanılmasından doğabilecek sorumluluk kullanıcıya aittir.

# 🛡️ Secheck — Web Güvenlik, Port & Tehdit İstihbarat Platformu

**Secheck**, FastAPI ile geliştirilmiş modern bir **Web Güvenlik Denetimi, Aktif/Pasif Keşif (Reconnaissance) ve Tehdit İstihbaratı Panelidir**. Kullanıcıya hem **Tam Denetim Modu** (14 TCP Port Banner yakalama ve 30 kritik dizin taraması dahil) hem de **Pasif / Güvenli Mod** (hedefe yalnızca 1 adet standart HTTP isteği göndererek SSL/TLS, HTTP başlıkları, çerezler, HTML kaynak kod kazıma, Google DoH SPF/DMARC ve Shodan InternetDB CVE analizi yapan mod) sunar.

---

## 🎯 Projenin Amacı

Web uygulamalarında sıkça unutulan güvenlik başlıklarını, zayıf çerez bayraklarını, süresi dolmak üzere olan SSL sertifikalarını, dış dünyaya açık unutulan yönetim/veritabanı portlarını (`21, 22, 23, 3306, 5432, 6379`), Shodan CVE zafiyetlerini, SPF/DMARC e-posta sahteciliği risklerini ve hassas dosyaları (`/.env`, `/.git/config`, `/backup.sql` vb.) tek bir ekran üzerinden tespit etmek ve doğrudan uygulanabilir sıkılaştırma (Remediation) önerileri sunmaktır.

---

## ✨ "Cyber-Security Glassmorphism" Arayüz Özellikleri

- **Derin Uzay Karanlık Teması (`#0B0F19`):** Göz yormayan siber güvenlik operasyon merkezi (SOC) renk paleti ve ince ızgara (grid) arka plan dokusu.
- **Buzlu Cam Kartlar (Glassmorphism):** `bg-slate-900/60 backdrop-blur-md border border-slate-800` sınıflarıyla yarı saydam, katmanlı modül kartları.
- **Tipografi Hiyerarşisi:** Başlık ve açıklamalar için okunabilirliği yüksek **Inter**, IP adresleri, HTTP başlıkları, protokoller ve dizin yolları için **JetBrains Mono** font ailesi.
- **Neon Vurgu ve Durum Rozetleri:** Siber Mavi (`cyan-400`) ve Neon Yeşil (`emerald-400`) ana vurgular; bulgu durumlarına göre **Yeşil (Güvenli)**, **Sarı (Uyarı / 403 Mevcut)** ve **Kırmızı (Eksik / Kritik Sızıntı)** rozet sistemi.
- **Canlı Tarama Animasyonu:** Analiz başlatıldığında paralel taramalar tamamlanana kadar ekranda beliren çift halkalı radar yükleme katmanı (*"Hedef analiz ediliyor, uç noktalar ve sertifikalar kontrol ediliyor..."*).

---

## 🔍 Kontrol Edilen Güvenlik Metrikleri

1. **Hedef İstihbaratı (Target Intel):**
   - `urllib.parse` ile URL normalizasyonu (`http/https` kontrolü ve saf `hostname` ayıklama).
   - `socket.gethostbyname()` ile IPv4 çözümlemesi ve `socket.getfqdn()` ile Reverse DNS (FQDN) tespiti.
2. **SSL/TLS Kriptografi Denetimi (Port 443):**
   - Sertifika Sağlayıcısı (`Issuer`), TLS protokol sürümü (`TLSv1.3`, `TLSv1.2`), bitiş tarihi (`UTC`) ve kalan gün sayısı hesabı.
3. **8 Koruyucu HTTP Güvenlik Başlığı:**
   - `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` (COOP), `Cross-Origin-Resource-Policy` (CORP).
4. **Sunucu Bilgi Sızıntısı & WAF/CDN Tespiti:**
   - `Server`, `X-Powered-By` ve `X-AspNet-Version` başlıklarının ifşa kontrolü.
   - Yanıt başlıkları ve çerez imzalarından **Cloudflare**, **AWS CloudFront**, **Akamai**, **Fastly**, **Sucuri**, **Imperva**, **Vercel Edge** ve **Azure Front Door** tespiti.
5. **Paralel Dizin & Dosya Keşfi (`ThreadPoolExecutor`):**
   - `max_workers=10` ve `timeout=2s` ile 5 kategoride kritik uç noktaların eşzamanlı taranması.
   - Yanlış pozitifleri (False Positive) önlemek adına `allow_redirects=False` kullanımı; yalnızca gerçek `200 OK` ve `403 Forbidden` yanıtlarının yakalanması.
   - `/robots.txt` mevcutsa içindeki `Disallow:` kurallarının otomatik ayıklanması.

---

## 📊 Ağırlıklı Puanlama Algoritması (0 – 100 Puan)

Toplam güvenlik skoru 4 ana kategorinin toplamından ve varsa **Kritik Zafiyet Cezalarından** oluşur:

| Kategori | Alt Metrik / Kontrol | Puan / Etki | Maksimum Puan |
| :--- | :--- | :---: | :---: |
| **1. Kriptografi & SSL** | Geçerli ve süresi dolmamış SSL Sertifikası | `+15` | **25 Puan** |
| | `TLSv1.3` kullanımı (`TLSv1.2` ise `+5` puan) | `+10` | |
| | SSL yok veya sertifika süresi dolmuş | `0` | |
| **2. HTTP Güvenlik Başlıkları** | `Content-Security-Policy` (CSP) | `+12` | **45 Puan** |
| | `Strict-Transport-Security` (HSTS) | `+10` | |
| | `X-Frame-Options` (XFO) | `+6` | |
| | `X-Content-Type-Options` (XCTO) | `+6` | |
| | `Referrer-Policy` (RP) | `+4` | |
| | `Permissions-Policy` (PP) | `+4` | |
| | `Cross-Origin-Opener-Policy` (COOP) | `+1.5` | |
| | `Cross-Origin-Resource-Policy` (CORP) | `+1.5` | |
| **3. Saldırı Yüzeyi & Sızıntı Önleme** | Başlangıç Puanı | `+20` | **20 Puan** |
| | `Server` / `X-Powered-By` / `X-AspNet-Version` sızıntısı | `-5` | |
| | Açık Yönetim Paneli veya API Dokümanı (`200 OK`) | `-5 / adet` | |
| | **Kritik Sızıntı** (`/.env`, `/.git/config` vb.) veya **Yüksek Risk** (`/backup.sql` vb.) `200 OK` | **Kategori Sıfırlanır (`0`) + Genel Toplama `-15` Ceza!** | |
| **4. Standartlar & Savunma Derinliği** | WAF / CDN Koruma Kalkanı Tespiti | `+5` | **10 Puan** |
| | `/.well-known/security.txt` (RFC 9116) Varlığı | `+5` | |
| **GENEL TOPLAM** | *(0'ın altına düşerse `0` olarak sabitlenir)* | **0 – 100** | **100 Puan** |

### Harf Notu Skalası

| Puan Aralığı | Harf Notu | Risk Durumu |
| :---: | :---: | :--- |
| `90 – 100` | **A+** | Mükemmel Güvenlik Duruşu |
| `80 – 89` | **A** | Güçlü Güvenlik Seviyesi |
| `70 – 79` | **B** | İyi (Küçük Eksikler Mevcut) |
| `60 – 69` | **C** | Orta Risk (Sıkılaştırma Gerekli) |
| `50 – 59` | **D** | Zayıf Koruma (Yüksek Risk) |
| `0 – 49` | **F** | Kritik Risk (Acil Müdahale Gerekli) |

---

## 🚀 Kurulum ve Çalıştırma Adımları

### 1. Gereksinimleri Yükleyin
Proje dizininde bulunan `requirements.txt` dosyasındaki bağımlılıkları kurun:

```bash
pip install -r requirements.txt
```

### 2. FastAPI Sunucusunu Başlatın
Uvicorn ile geliştirme sunucusunu çalıştırın:

```bash
uvicorn main:app --reload
```
*(Windows ortamında Python başlatıcısı kullanıyorsanız: `py -m uvicorn main:app --reload`)*

### 3. Tarayıcıda Açın
Tarayıcınızdan aşağıdaki adrese gidin:

```text
http://127.0.0.1:8000
```

---

## 📁 Proje Dizin Yapısı

```text
├── main.py                # FastAPI uygulaması, keşif motoru ve ağırlıklı puanlama algoritması
├── requirements.txt       # Python bağımlılıkları (fastapi, uvicorn, requests, jinja2)
├── README.md              # Proje dokümantasyonu ve matematiksel algoritma tablosu
└── templates/
    └── index.html         # Cyber-Security Glassmorphism arayüz şablonu
```
