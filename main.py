import os
import re
import socket
import sqlite3
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# FastAPI uygulama nesnesi ve Jinja2 şablon dizini yapılandırması
app = FastAPI(title="Secheck // Web Security, Port & Threat Intelligence Platform")
templates = Jinja2Templates(directory="templates")

# SQLite veritabanı dosya yolu
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_history.db")

# Hedef sunucular tarafından bot engeline takılmamak için kullanılan standart tarayıcı User-Agent başlığı
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Bilinen WAF / CDN / Edge sağlayıcılarının Server başlığı değerleri
# Bu değerlerin Server başlığında görünmesi bir güvenlik açığı (sızıntı) DEĞİLDİR; aksine koruma katmanıdır.
KNOWN_PROXY_SERVER_NAMES = (
    "cloudflare",
    "akamaighost",
    "akamai",
    "cloudfront",
    "amazons3",
    "awselb",
    "fastly",
    "vercel",
    "netlify",
    "sucuri",
    "incapsula",
    "imperva",
    "gws",
    "esf",
    "sffe",
    "ghs",
    "envoy",
    "fly.io",
    "railway",
    "render",
    "azure",
)

# Sürüm numarası tespiti için düzenli ifade (Örn: Apache/2.4.52, nginx/1.18.0, PHP/8.1.2)
VERSION_NUMBER_REGEX = re.compile(r"\d+\.\d+(?:\.\d+)?")

# Kaynak Kod & CTF İstihbarat Kazıyıcı (HTML Scraper) için Regex desenleri
HTML_COMMENT_REGEX = re.compile(r"<!--([\s\S]*?)-->")
HIDDEN_INPUT_TAG_REGEX = re.compile(r"<input\b[^>]*\btype\s*=\s*['\"]hidden['\"][^>]*>", re.IGNORECASE)
ATTR_NAME_REGEX = re.compile(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ATTR_VALUE_REGEX = re.compile(r"\bvalue\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,12}\b")
PRIVATE_IP_REGEX = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?![\d.])"
)
SCRIPT_SRC_REGEX = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)

# ---------------------------------------------------------------------------
# AEGIS V3.0: AKTİF PORT TARAYICI VE BANNER AVCISI HEDEF PORT LİSTESİ (14 PORT)
# ---------------------------------------------------------------------------
CRITICAL_TCP_PORTS_SPEC = [
    {"port": 21, "service": "FTP", "high_risk": True, "desc": "Dosya Aktarım Protokolü"},
    {"port": 22, "service": "SSH", "high_risk": True, "desc": "Uzaktan Kabuk Erişimi"},
    {"port": 23, "service": "Telnet", "high_risk": True, "desc": "Şifresiz Terminal Erişimi"},
    {"port": 25, "service": "SMTP", "high_risk": False, "desc": "E-Posta Gönderim Aktarımı"},
    {"port": 53, "service": "DNS", "high_risk": False, "desc": "Alan Adı Çözümleme Servisi"},
    {"port": 80, "service": "HTTP", "high_risk": False, "desc": "Standart Web Sunucusu"},
    {"port": 110, "service": "POP3", "high_risk": False, "desc": "Posta Kutusu Erişimi"},
    {"port": 143, "service": "IMAP", "high_risk": False, "desc": "E-Posta Senkronizasyon"},
    {"port": 443, "service": "HTTPS", "high_risk": False, "desc": "Şifreli Web Sunucusu (TLS)"},
    {"port": 3306, "service": "MySQL", "high_risk": True, "desc": "MySQL / MariaDB Veritabanı"},
    {"port": 5432, "service": "PostgreSQL", "high_risk": True, "desc": "PostgreSQL Veritabanı"},
    {"port": 6379, "service": "Redis", "high_risk": True, "desc": "Bellek İçi Veri Deposu"},
    {"port": 8080, "service": "HTTP-Proxy", "high_risk": False, "desc": "Alternatif Web / Proxy"},
    {"port": 8443, "service": "HTTPS-Alt", "high_risk": False, "desc": "Alternatif HTTPS / Panel"},
]

HIGH_RISK_PORTS_SET = {21, 22, 23, 3306, 5432, 6379}

# ---------------------------------------------------------------------------
# KONTROL EDİLECEK 8 KORUYUCU HTTP GÜVENLİK BAŞLIĞI TANIMLARI
# ---------------------------------------------------------------------------
SECURITY_HEADERS_SPEC = [
    {
        "header": "Strict-Transport-Security",
        "short": "HSTS",
        "weight": 10,
        "description": "HTTPS bağlantısını zorunlu kılar ve protokol düşürme (SSL Strip) saldırılarını önler.",
        "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "critical": True,
    },
    {
        "header": "Content-Security-Policy",
        "short": "CSP",
        "weight": 12,
        "description": "XSS ve veri enjeksiyonu saldırılarına karşı yürütülebilir kaynak politikasını sınırlar.",
        "remediation": "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests;",
        "critical": True,
    },
    {
        "header": "X-Frame-Options",
        "short": "XFO",
        "weight": 6,
        "description": "Clickjacking saldırılarına karşı sayfanın harici iframe içinde gömülmesini engeller.",
        "remediation": "X-Frame-Options: DENY",
        "critical": True,
    },
    {
        "header": "X-Content-Type-Options",
        "short": "XCTO",
        "weight": 6,
        "description": "Tarayıcının MIME-sniffing yapmasını engelleyerek içerik tipini korur.",
        "remediation": "X-Content-Type-Options: nosniff",
        "critical": True,
    },
    {
        "header": "Referrer-Policy",
        "short": "RP",
        "weight": 4,
        "description": "Çapraz kaynak isteklerinde gönderilen Referer başlığındaki URL bilgisini sınırlar.",
        "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
        "critical": False,
    },
    {
        "header": "Permissions-Policy",
        "short": "PP",
        "weight": 4,
        "description": "Kamera, mikrofon, konum gibi hassas tarayıcı API'lerine erişimi kısıtlar.",
        "remediation": "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()",
        "critical": False,
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "short": "COOP",
        "weight": 1.5,
        "description": "Üst düzey belgenin diğer kaynaklarla tarayıcı pencere bağlamını izole eder.",
        "remediation": "Cross-Origin-Opener-Policy: same-origin",
        "critical": False,
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "short": "CORP",
        "weight": 1.5,
        "description": "Statik ve dinamik kaynakların başka siteler tarafından yüklenmesini sınırlar.",
        "remediation": "Cross-Origin-Resource-Policy: same-origin",
        "critical": False,
    },
]

# ---------------------------------------------------------------------------
# BİLGİ SIZINTISI (INFORMATION DISCLOSURE) BAŞLIK TANIMLARI
# ---------------------------------------------------------------------------
DISCLOSURE_HEADERS_SPEC = [
    {
        "header": "Server",
        "description": "Arka uç web sunucusunun tam sürüm numarasını (örn. nginx/1.18.0) ifşa edip etmediğini denetler.",
        "remediation": "server_tokens off; # Nginx  |  ServerTokens Prod # Apache",
    },
    {
        "header": "X-Powered-By",
        "description": "Arka uç uygulama çatısını ve sürümünü (PHP, Express, ASP.NET vb.) ifşa eder.",
        "remediation": "app.disable('x-powered-by'); // Express.js  |  expose_php = Off ; php.ini",
    },
    {
        "header": "X-AspNet-Version",
        "description": "Kullanılan tam .NET Framework sürüm bilgisini yanıt başlığında sızdırır.",
        "remediation": "<httpRuntime enableVersionHeader=\"false\" /> <!-- web.config -->",
    },
]

# ---------------------------------------------------------------------------
# DİZİN VE DOSYA KEŞFİ (DIRECTORY ENUMERATION) HEDEF LİSTESİ (5 KATEGORİ)
# ---------------------------------------------------------------------------
DIRECTORY_TARGETS_SPEC = [
    # 1. [KRİTİK SIZINTI - Hassas Dosyalar]
    {"path": "/.env", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "env"},
    {"path": "/.git/config", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "git"},
    {"path": "/phpinfo.php", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "phpinfo"},
    {"path": "/config.php", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "non_empty_code"},
    {"path": "/wp-config.php.bak", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "wp_config"},
    {"path": "/.DS_Store", "category": "KRİTİK SIZINTI - Hassas Dosyalar", "severity_on_200": "critical", "validator": "ds_store"},
    # 2. [YÜKSEK RİSK - Yedek & Log]
    {"path": "/backup.zip", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "binary_archive"},
    {"path": "/backup.sql", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "sql"},
    {"path": "/db.sql", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "sql"},
    {"path": "/debug.log", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "log"},
    {"path": "/error.log", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "log"},
    {"path": "/server-status", "category": "YÜKSEK RİSK - Yedek & Log", "severity_on_200": "critical", "validator": "server_status"},
    # 3. [YÖNETİM PANELLERİ - Admin]
    {"path": "/admin", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    {"path": "/login", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    {"path": "/wp-admin", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    {"path": "/administrator", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    {"path": "/phpmyadmin", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "phpmyadmin"},
    {"path": "/dashboard", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    {"path": "/cpanel", "category": "YÖNETİM PANELLERİ - Admin", "severity_on_200": "critical", "validator": "admin_html"},
    # 4. [API & GELİŞTİRİCİ]
    {"path": "/swagger.json", "category": "API & GELİŞTİRİCİ", "severity_on_200": "warning", "validator": "openapi_json"},
    {"path": "/openapi.json", "category": "API & GELİŞTİRİCİ", "severity_on_200": "warning", "validator": "openapi_json"},
    {"path": "/api-docs", "category": "API & GELİŞTİRİCİ", "severity_on_200": "warning", "validator": "api_docs"},
    {"path": "/graphql", "category": "API & GELİŞTİRİCİ", "severity_on_200": "critical", "validator": "graphql"},
    {"path": "/api/v1", "category": "API & GELİŞTİRİCİ", "severity_on_200": "warning", "validator": "json_api"},
    {"path": "/package.json", "category": "API & GELİŞTİRİCİ", "severity_on_200": "critical", "validator": "package_json"},
    {"path": "/actuator/health", "category": "API & GELİŞTİRİCİ", "severity_on_200": "critical", "validator": "actuator"},
    # 5. [STANDART & KEŞİF]
    {"path": "/robots.txt", "category": "STANDART & KEŞİF", "severity_on_200": "safe", "validator": "robots"},
    {"path": "/sitemap.xml", "category": "STANDART & KEŞİF", "severity_on_200": "safe", "validator": "xml"},
    {"path": "/.well-known/security.txt", "category": "STANDART & KEŞİF", "severity_on_200": "safe", "validator": "security_txt"},
    {"path": "/humans.txt", "category": "STANDART & KEŞİF", "severity_on_200": "safe", "validator": "plain_text"},
    {"path": "/crossdomain.xml", "category": "STANDART & KEŞİF", "severity_on_200": "safe", "validator": "xml"},
]


# ---------------------------------------------------------------------------
# AEGIS V3.0 - GELİŞTİRME 5: SQLITE TARAMA GEÇMİŞİ (SCAN HISTORY) YÖNETİMİ
# ---------------------------------------------------------------------------
def init_history_db() -> None:
    """aegis_history.db SQLite veritabanını ve scan_history tablosunu oluşturur."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ipv4 TEXT NOT NULL,
                total_score REAL NOT NULL,
                grade TEXT NOT NULL,
                open_ports_count INTEGER NOT NULL,
                cve_count INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan_history(
    hostname: str,
    ipv4: str,
    total_score: float | int,
    grade: str,
    open_ports_count: int,
    cve_count: int,
) -> None:
    """Başarılı bir analizin özet metriklerini SQLite veritabanına kaydeder."""
    try:
        init_history_db()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO scan_history (
                    hostname, ipv4, total_score, grade, open_ports_count, cve_count, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (hostname, ipv4, float(total_score), grade, int(open_ports_count), int(cve_count), ts),
            )
            conn.commit()
    except Exception:
        pass


def get_recent_scans(limit: int = 10) -> list[dict]:
    """Son yapılan analizleri (varsayılan 10 kayıt) yeniden eskiye doğru döndürür."""
    try:
        init_history_db()
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, hostname, ipv4, total_score, grade, open_ports_count, cve_count, timestamp
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result = []
        for r in rows:
            sc = r["total_score"]
            sc_fmt = int(sc) if isinstance(sc, float) and sc.is_integer() else round(sc, 1)
            result.append(
                {
                    "id": r["id"],
                    "hostname": r["hostname"],
                    "ipv4": r["ipv4"],
                    "total_score": sc_fmt,
                    "grade": r["grade"],
                    "open_ports_count": r["open_ports_count"],
                    "cve_count": r["cve_count"],
                    "timestamp": r["timestamp"],
                }
            )
        return result
    except Exception:
        return []


def clear_scan_history() -> None:
    """SQLite veritabanındaki tüm tarama geçmişini temizler."""
    try:
        init_history_db()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM scan_history")
            conn.commit()
    except Exception:
        pass


# Uygulama başlangıcında veritabanını hazırla
init_history_db()


def format_num(val: float | int) -> int | float:
    """Ondalık kısmı sıfır olan sayıları (örn: 45.0 -> 45) tam sayıya çevirerek temiz görünüm sağlar."""
    if isinstance(val, float) and val.is_integer():
        return int(val)
    return round(val, 1)


def extract_root_domain(hostname: str) -> str:
    """Alt alan adlarından kök alan adını (örn: app.sub.github.com -> github.com, site.com.tr -> site.com.tr) ayıklar."""
    parts = [p for p in hostname.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    multi_tlds = {"com.tr", "org.tr", "gov.tr", "edu.tr", "net.tr", "co.uk", "org.uk", "ac.uk"}
    last_two = ".".join(parts[-2:])
    if last_two in multi_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# 2. ADIM FONKSİYONU: URL TEMİZLEME VE DNS / IP İSTİHBARATI
# ---------------------------------------------------------------------------
def parse_and_resolve_target(raw_url: str) -> dict:
    """
    Kullanıcının girdiği URL'yi urllib.parse ile normalize eder,
    protokol yoksa 'https://' ekler ve socket ile IPv4 + FQDN (Reverse DNS) çözer.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise ValueError("Lütfen geçerli bir URL veya alan adı girin.")

    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    protocol = parsed.scheme.lower()
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Girilen adresten geçerli bir alan adı (hostname) ayıklanamadı.")

    ipv4_address = socket.gethostbyname(hostname)
    fqdn = socket.getfqdn(ipv4_address)

    base_url = f"{protocol}://{hostname}"
    if parsed.port:
        base_url = f"{base_url}:{parsed.port}"

    return {
        "input_url": raw_url.strip(),
        "normalized_url": cleaned,
        "base_url": base_url,
        "protocol": protocol.upper(),
        "hostname": hostname,
        "root_domain": extract_root_domain(hostname),
        "ipv4": ipv4_address,
        "fqdn": fqdn,
    }


# ---------------------------------------------------------------------------
# AEGIS V3.0 - GELİŞTİRME 2: AKTİF TCP PORT TARAYICI VE BANNER AVCISI
# ---------------------------------------------------------------------------
def clean_banner_bytes(raw_bytes: bytes) -> str:
    """
    Okunan ham baytları decode('utf-8', errors='ignore') ile çözer,
    HTTP yanıtı ise ilk durum satırını ve Server başlığını birleştirir,
    kontrol karakterlerini temizleyip okunabilir tek satır metin haline getirir.
    """
    if not raw_bytes:
        return ""
    decoded = raw_bytes.decode("utf-8", errors="ignore")
    lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    if not lines:
        return ""

    # HTTP yanıtı ise ilk satır (örn: HTTP/1.1 200 OK) ve varsa Server başlığını yakala
    first_line = lines[0]
    server_line = None
    for ln in lines[1:]:
        if ln.lower().startswith("server:"):
            server_line = ln
            break

    combined = f"{first_line} | {server_line}" if server_line else first_line
    # Kontrol karakterlerini ve yazdırılamayan baytları temizle
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", combined)
    cleaned = " ".join(cleaned.split())
    return cleaned[:140]


def scan_ports_and_banners(ipv4: str, hostname: str) -> dict:
    """
    AEGIS V3.0 - Geliştirme 2:
    14 kritik TCP portunu ThreadPoolExecutor(max_workers=14) ile paralel tarar (timeout=1.2s).
    Port açıksa (connect_ex == 0):
    1) Önce sock.recv(128) ile servisin kendiliğinden gönderdiği başlangıç banner'ını okumayı dener.
    2) Veri gelmezse HTTP/uygulama tetikleme (probe) paketi gönderip ilk satırı veya Server başlığını yakalar.
    Tehlikeli yönetim/veritabanı portları (21, 22, 23, 3306, 5432, 6379) açıksa Yüksek Risk olarak işaretler.
    """

    def probe_single_port(spec: dict) -> dict:
        port = spec["port"]
        service = spec["service"]
        is_high_risk = port in HIGH_RISK_PORTS_SET
        banner_text = ""
        is_open = False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            result = sock.connect_ex((ipv4, port))
            if result == 0:
                is_open = True
                raw_data = b""
                # 1. Aşama: Servisin kendiliğinden gönderdiği banner'ı (SSH, FTP, SMTP, MySQL vb.) oku
                try:
                    sock.settimeout(0.55)
                    raw_data = sock.recv(128)
                except (socket.timeout, OSError):
                    raw_data = b""

                banner_text = clean_banner_bytes(raw_data)

                # 2. Aşama: Kendiliğinden veri göndermediyse HTTP HEAD probe paketi gönder
                if not banner_text:
                    try:
                        sock.settimeout(0.65)
                        probe_payload = (
                            b"HEAD / HTTP/1.0\r\nHost: "
                            + hostname.encode("utf-8", errors="ignore")
                            + b"\r\nUser-Agent: Secheck-Scanner\r\n\r\n"
                        )
                        sock.sendall(probe_payload)
                        probe_resp = sock.recv(256)
                        banner_text = clean_banner_bytes(probe_resp)
                    except (socket.timeout, OSError):
                        banner_text = ""

                if not banner_text:
                    if port in (443, 8443):
                        banner_text = "TLS/SSL El Sıkışma Portu Aktif (Şifreli Kanal)"
                    else:
                        banner_text = f"{service} Servisi Aktif (Sessiz Yanıt)"
        except Exception:
            is_open = False
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if is_open:
            if is_high_risk:
                status = "critical"
                badge = "YÜKSEK RİSKLİ AÇIK PORT (-5 PUAN)"
            else:
                status = "safe"
                badge = "AÇIK (AKTİF SERVİS)"
        else:
            status = "closed"
            badge = "KAPALI / FİLTRELİ"

        return {
            "port": port,
            "service": service,
            "desc": spec["desc"],
            "is_open": is_open,
            "high_risk": is_high_risk and is_open,
            "banner": banner_text if is_open else "—",
            "status": status,
            "badge": badge,
        }

    with ThreadPoolExecutor(max_workers=14) as executor:
        all_ports = list(executor.map(probe_single_port, CRITICAL_TCP_PORTS_SPEC))

    open_ports = [p for p in all_ports if p["is_open"]]
    high_risk_open = [p for p in open_ports if p["high_risk"]]

    return {
        "total_scanned": len(CRITICAL_TCP_PORTS_SPEC),
        "open_count": len(open_ports),
        "high_risk_count": len(high_risk_open),
        "open_ports": open_ports,
        "high_risk_ports": high_risk_open,
        "all_ports": all_ports,
    }


# ---------------------------------------------------------------------------
# AEGIS V3.0 - GELİŞTİRME 3: SHODAN INTERNETDB & CVE ZAFİYET İSTİHBARATI
# ---------------------------------------------------------------------------
def query_shodan_internetdb(ipv4: str) -> dict:
    """
    AEGIS V3.0 - Geliştirme 3:
    Hedefin IPv4 adresi için https://internetdb.shodan.io/{ipv4} servisine (timeout=3)
    GET isteği atar. Bilinen CVE zafiyetlerini (vulns), CPE yazılım/donanım imzalarını (cpes),
    hostnames ve tags bilgilerini çeker.
    """
    url = f"https://internetdb.shodan.io/{ipv4}"
    try:
        resp = requests.get(
            url,
            timeout=3,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = sorted(set(data.get("vulns") or []))
            cpes = list(data.get("cpes") or [])
            hostnames = list(data.get("hostnames") or [])
            tags = list(data.get("tags") or [])
            shodan_ports = list(data.get("ports") or [])

            return {
                "available": True,
                "ipv4": ipv4,
                "vulns": vulns,
                "cve_count": len(vulns),
                "cpes": cpes[:20],
                "hostnames": hostnames[:15],
                "tags": tags[:15],
                "shodan_ports": shodan_ports,
                "status": "critical" if vulns else "safe",
                "message": None,
            }
        if resp.status_code == 404:
            return {
                "available": True,
                "ipv4": ipv4,
                "vulns": [],
                "cve_count": 0,
                "cpes": [],
                "hostnames": [],
                "tags": [],
                "shodan_ports": [],
                "status": "safe",
                "message": "Bu IPv4 adresi için Shodan InternetDB üzerinde kayıtlı CVE zafiyeti bulunmuyor.",
            }
        return {
            "available": False,
            "ipv4": ipv4,
            "vulns": [],
            "cve_count": 0,
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "shodan_ports": [],
            "status": "unavailable",
            "message": f"Shodan InternetDB servisi HTTP {resp.status_code} yanıtı döndürdü.",
        }
    except Exception:
        return {
            "available": False,
            "ipv4": ipv4,
            "vulns": [],
            "cve_count": 0,
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "shodan_ports": [],
            "status": "timeout",
            "message": "Shodan InternetDB servisi 3 saniye içinde yanıt vermedi.",
        }


# ---------------------------------------------------------------------------
# AEGIS V3.0 - GELİŞTİRME 4: DNS & E-POSTA SAHTECİLİĞİ (SPF / DMARC / MX) DENETİMİ
# ---------------------------------------------------------------------------
def inspect_dns_email_security(hostname: str) -> dict:
    """
    AEGIS V3.0 - Geliştirme 4:
    Google DNS-over-HTTPS JSON API'sini (https://dns.google/resolve) kullanarak
    kök domainin MX, SPF (v=spf1) ve _dmarc.{domain} adresinin DMARC (v=DMARC1) kayıtlarını sorgular.
    """
    root_domain = extract_root_domain(hostname)

    def doh_query(qname: str, qtype: str) -> list[str]:
        try:
            resp = requests.get(
                "https://dns.google/resolve",
                params={"name": qname, "type": qtype},
                timeout=3,
                headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return []
            payload = resp.json()
            answers = payload.get("Answer") or []
            records = []
            for ans in answers:
                raw_data = str(ans.get("data", "")).strip()
                # TXT kayıtlarındaki çift tırnakları temizle
                if raw_data.startswith('"') and raw_data.endswith('"'):
                    raw_data = raw_data[1:-1].replace('" "', "")
                else:
                    raw_data = raw_data.strip('"')
                if raw_data:
                    records.append(raw_data)
            return records
        except Exception:
            return []

    # 3 DNS sorgusunu paralel çalıştır (MX, TXT -> SPF, _dmarc TXT -> DMARC)
    with ThreadPoolExecutor(max_workers=3) as executor:
        fut_mx = executor.submit(doh_query, root_domain, "MX")
        fut_txt = executor.submit(doh_query, root_domain, "TXT")
        fut_dmarc = executor.submit(doh_query, f"_dmarc.{root_domain}", "TXT")

        mx_raw = fut_mx.result()
        txt_raw = fut_txt.result()
        dmarc_raw = fut_dmarc.result()

    # 1. MX Kayıtlarını Ayıkla
    mx_records = []
    for item in mx_raw:
        clean_mx = item.rstrip(".")
        if clean_mx and clean_mx not in mx_records:
            mx_records.append(clean_mx)

    # 2. SPF Kaydını ve Politikasını (-all vs ~all) Analiz Et
    spf_record = None
    for txt in txt_raw:
        if "v=spf1" in txt.lower():
            spf_record = txt
            break

    if spf_record:
        spf_lower = spf_record.lower()
        if "-all" in spf_lower:
            spf_mode = "hardfail"
            spf_status = "safe"
            spf_badge = "GÜVENLİ (-all · HARDFAIL)"
            spf_desc = "Yetkisiz sunuculardan gelen e-postalar kesin olarak reddedilir (-all)."
        elif "~all" in spf_lower:
            spf_mode = "softfail"
            spf_status = "warning"
            spf_badge = "ESNEK (~all · SOFTFAIL)"
            spf_desc = "Yetkisiz e-postalar kabul edilir ancak spam olarak işaretlenir (~all)."
        elif "+all" in spf_lower or "?all" in spf_lower:
            spf_mode = "permissive"
            spf_status = "critical"
            spf_badge = "TEHLİKELİ (+all / ?all)"
            spf_desc = "SPF politikası tüm sunuculara izin veriyor veya nötr davranıyor."
        else:
            spf_mode = "redirect_or_custom"
            spf_status = "safe"
            spf_badge = "AKTİF (ÖZEL / REDIRECT)"
            spf_desc = "SPF kaydı tanımlı (redirect veya özel mekanizma kullanılıyor)."
    else:
        spf_mode = "missing"
        spf_status = "critical"
        spf_badge = "EKSİK (SPF KAYDI YOK)"
        spf_desc = "Kök alan adında v=spf1 TXT kaydı bulunamadı; alan adı e-posta sahteciliğine (Spoofing) açık."

    # 3. DMARC Kaydını ve Politikasını (p=reject, p=quarantine, p=none) Analiz Et
    dmarc_record = None
    for txt in dmarc_raw:
        if "v=dmarc1" in txt.lower():
            dmarc_record = txt
            break

    dmarc_policy = None
    if dmarc_record:
        m_pol = re.search(r"\bp\s*=\s*([a-zA-Z]+)", dmarc_record, re.IGNORECASE)
        dmarc_policy = m_pol.group(1).lower() if m_pol else "unknown"

        if dmarc_policy == "reject":
            dmarc_status = "safe"
            dmarc_badge = "GÜVENLİ (p=reject)"
            dmarc_desc = "SPF/DKIM doğrulamasından geçemeyen sahte e-postalar doğrudan reddedilir."
        elif dmarc_policy == "quarantine":
            dmarc_status = "safe"
            dmarc_badge = "KORUMALI (p=quarantine)"
            dmarc_desc = "Şüpheli e-postalar karantinaya (Spam klasörüne) alınır."
        elif dmarc_policy == "none":
            dmarc_status = "warning"
            dmarc_badge = "İZLEME MODU (p=none)"
            dmarc_desc = "DMARC kaydı mevcut ancak sahte e-postalar engellenmiyor (yalnızca raporlanıyor)."
        else:
            dmarc_status = "warning"
            dmarc_badge = f"POLİTİKA: {dmarc_policy.upper()}"
            dmarc_desc = "DMARC kaydı mevcut."
    else:
        dmarc_status = "critical"
        dmarc_badge = "EKSİK (DMARC YOK)"
        dmarc_desc = f"_dmarc.{root_domain} adresinde DMARC politikası tanımlanmamış."

    return {
        "root_domain": root_domain,
        "mx_records": mx_records[:10],
        "has_mx": len(mx_records) > 0,
        "spf": {
            "present": spf_record is not None,
            "record": spf_record or "Tanımlanmamış",
            "mode": spf_mode,
            "status": spf_status,
            "badge": spf_badge,
            "desc": spf_desc,
        },
        "dmarc": {
            "present": dmarc_record is not None,
            "record": dmarc_record or "Tanımlanmamış",
            "policy": dmarc_policy or "Yok",
            "status": dmarc_status,
            "badge": dmarc_badge,
            "desc": dmarc_desc,
        },
    }


# ---------------------------------------------------------------------------
# 3. ADIM YARDIMCI FONKSİYONLARI: WAF/CDN, ÇEREZ DENETÇİSİ VE HTML KAZIYICI
# ---------------------------------------------------------------------------
def detect_waf_cdn(headers: dict, cookies: list[str]) -> list[str]:
    """HTTP yanıt başlıkları ve çerez imzalarından bilinen WAF/CDN sağlayıcılarını tespit eder."""
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    cookie_names = [c.lower() for c in cookies]
    all_header_text = " ".join(f"{k}:{v}" for k, v in lower_headers.items())

    detected = []

    if (
        "cf-ray" in lower_headers
        or "cf-cache-status" in lower_headers
        or "cloudflare" in lower_headers.get("server", "")
        or any(c.startswith("__cf") or c.startswith("cf_") for c in cookie_names)
    ):
        detected.append("Cloudflare")

    if (
        "x-amz-cf-id" in lower_headers
        or "x-amz-cf-pop" in lower_headers
        or "cloudfront" in lower_headers.get("via", "")
        or "cloudfront" in lower_headers.get("server", "")
    ):
        detected.append("AWS CloudFront")

    if (
        "x-akamai-transformed" in lower_headers
        or "akamai" in all_header_text
        or any("akamai" in c or "ak_bmsc" in c for c in cookie_names)
    ):
        detected.append("Akamai")

    if "x-fastly-request-id" in lower_headers or "fastly" in all_header_text:
        detected.append("Fastly CDN")

    if "x-sucuri-id" in lower_headers or "sucuri" in lower_headers.get("server", ""):
        detected.append("Sucuri WAF")

    if (
        "x-iinfo" in lower_headers
        or "incapsula" in all_header_text
        or any("incap_ses" in c or "visid_incap" in c for c in cookie_names)
    ):
        detected.append("Imperva / Incapsula")

    if "x-vercel-id" in lower_headers or "vercel" in lower_headers.get("server", ""):
        detected.append("Vercel Edge")

    if "x-azure-ref" in lower_headers:
        detected.append("Azure Front Door")

    return detected


def evaluate_server_header(header_name: str, raw_value: str | None) -> dict:
    """
    Server, X-Powered-By ve X-AspNet-Version başlıklarını analiz eder.
    Cloudflare/WAF veya sürüm içermeyen Server başlıklarında puan kırmaz.
    """
    if not raw_value or not raw_value.strip():
        return {
            "leaked": False,
            "is_proxy_masked": False,
            "value": "Gizlenmiş (Başlık Yok)",
            "status": "safe",
            "badge": "GÜVENLİ (GİZLİ)",
        }

    val = raw_value.strip()
    val_lower = val.lower()

    if header_name == "Server":
        if any(proxy in val_lower for proxy in KNOWN_PROXY_SERVER_NAMES):
            return {
                "leaked": False,
                "is_proxy_masked": True,
                "value": val,
                "status": "safe",
                "badge": "KORUMALI (WAF/EDGE PROXY)",
            }
        if not VERSION_NUMBER_REGEX.search(val):
            return {
                "leaked": False,
                "is_proxy_masked": False,
                "value": val,
                "status": "safe",
                "badge": "GÜVENLİ (SÜRÜM GİZLİ)",
            }

    return {
        "leaked": True,
        "is_proxy_masked": False,
        "value": val,
        "status": "leak",
        "badge": "SÜRÜM SIZINTISI (-5 PUAN)",
    }


def extract_raw_set_cookie_headers(response: requests.Response) -> list[str]:
    """
    Ekstra ağ isteği atmadan mevcut yanıt (ve varsa yönlendirme geçmişi) içindeki
    tüm Set-Cookie başlık satırlarını eksiksiz olarak ayıklar.
    """
    raw_cookies: list[str] = []
    all_responses = list(response.history) + [response]

    for resp in all_responses:
        if hasattr(resp.raw, "headers"):
            raw_hdrs = resp.raw.headers
            if hasattr(raw_hdrs, "getlist"):
                raw_cookies.extend(raw_hdrs.getlist("Set-Cookie"))
                continue
            if hasattr(raw_hdrs, "get_all"):
                raw_cookies.extend(raw_hdrs.get_all("Set-Cookie") or [])
                continue
        sc = resp.headers.get("Set-Cookie")
        if sc:
            raw_cookies.append(sc)

    seen = set()
    unique_cookies = []
    for item in raw_cookies:
        if item not in seen:
            seen.add(item)
            unique_cookies.append(item)
    return unique_cookies


def analyze_cookies(response: requests.Response) -> dict:
    """
    Çerez (Cookie) Güvenliği Denetçisi:
    Yanıttaki Set-Cookie başlıklarında Secure, HttpOnly ve SameSite bayraklarını kontrol eder.
    """
    raw_set_cookies = extract_raw_set_cookie_headers(response)
    parsed_cookies = []
    missing_flags_total = 0

    for raw_line in raw_set_cookies:
        segments = [seg.strip() for seg in raw_line.split(";") if seg.strip()]
        if not segments:
            continue

        first_seg = segments[0]
        cookie_name = first_seg.split("=", 1)[0].strip() if "=" in first_seg else first_seg
        attrs = segments[1:]
        attrs_lower = [a.lower() for a in attrs]

        has_secure = any(a == "secure" for a in attrs_lower)
        has_httponly = any(a == "httponly" for a in attrs_lower)
        samesite_val = None
        for a in attrs:
            if a.lower().startswith("samesite"):
                parts = a.split("=", 1)
                samesite_val = parts[1].strip() if len(parts) > 1 else "Tanımlı"
                break

        missing_list = []
        if not has_secure:
            missing_list.append("Secure")
        if not has_httponly:
            missing_list.append("HttpOnly")
        if not samesite_val:
            missing_list.append("SameSite")

        missing_flags_total += len(missing_list)

        if not missing_list:
            status = "safe"
            badge = "TAM KORUMALI"
        elif len(missing_list) == 1:
            status = "warning"
            badge = f"EKSİK: {missing_list[0]}"
        else:
            status = "critical"
            badge = f"GÜVENSİZ ({len(missing_list)} BAYRAK EKSİK)"

        parsed_cookies.append(
            {
                "name": cookie_name,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": samesite_val or "Yok",
                "has_samesite": bool(samesite_val),
                "missing_flags": missing_list,
                "status": status,
                "badge": badge,
            }
        )

    penalty = min(4.0, float(missing_flags_total))

    return {
        "has_cookies": len(parsed_cookies) > 0,
        "cookie_count": len(parsed_cookies),
        "cookies": parsed_cookies,
        "missing_flags_total": missing_flags_total,
        "penalty": format_num(penalty),
    }


def scrape_html_intelligence(html_text: str) -> dict:
    """
    CTF Odaklı Kaynak Kod & İstihbarat Kazıyıcı (HTML Scraper):
    Mevcut response.text üzerinde ekstra ağ isteği atmadan yorumları, gizli inputları,
    e-posta / dahili IP sızıntılarını ve JS kütüphanelerini ayıklar.
    """
    source = (html_text or "")[:250_000]

    comments = []
    seen_comments = set()
    for match in HTML_COMMENT_REGEX.finditer(source):
        raw_comment = match.group(1).strip()
        if not raw_comment or len(raw_comment) < 4:
            continue
        lower_c = raw_comment.lower()
        if lower_c.startswith("[if") or lower_c.startswith("<![endif") or "ko " in lower_c[:6]:
            continue
        cleaned_comment = " ".join(raw_comment.split())
        if len(cleaned_comment) > 180:
            cleaned_comment = cleaned_comment[:177] + "..."
        if cleaned_comment not in seen_comments:
            seen_comments.add(cleaned_comment)
            comments.append(cleaned_comment)
            if len(comments) >= 10:
                break

    hidden_inputs = []
    seen_inputs = set()
    for tag_match in HIDDEN_INPUT_TAG_REGEX.finditer(source):
        tag_str = tag_match.group(0)
        name_m = ATTR_NAME_REGEX.search(tag_str)
        val_m = ATTR_VALUE_REGEX.search(tag_str)
        inp_name = name_m.group(1).strip() if name_m else "(isimsiz)"
        inp_val = val_m.group(1).strip() if val_m else ""
        if len(inp_val) > 80:
            inp_val = inp_val[:77] + "..."
        key = (inp_name, inp_val)
        if key not in seen_inputs:
            seen_inputs.add(key)
            hidden_inputs.append({"name": inp_name, "value": inp_val or "(boş)"})
            if len(hidden_inputs) >= 15:
                break

    ignored_email_exts = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".ttf")
    emails = []
    seen_emails = set()
    for em_match in EMAIL_REGEX.finditer(source):
        email_str = em_match.group(0).lower()
        if email_str.endswith(ignored_email_exts):
            continue
        if email_str not in seen_emails:
            seen_emails.add(email_str)
            emails.append(email_str)
            if len(emails) >= 15:
                break

    private_ips = []
    seen_ips = set()
    for ip_match in PRIVATE_IP_REGEX.finditer(source):
        ip_str = ip_match.group(0)
        octets = ip_str.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            if ip_str not in seen_ips:
                seen_ips.add(ip_str)
                private_ips.append(ip_str)
                if len(private_ips) >= 15:
                    break

    known_libs = (
        "jquery",
        "bootstrap",
        "react",
        "vue",
        "angular",
        "axios",
        "lodash",
        "moment",
        "gsap",
        "three",
        "chart",
        "alpine",
        "htmx",
        "tailwind",
        "swiper",
        "sweetalert",
        "dompurify",
    )
    js_libraries = []
    seen_scripts = set()
    for sc_match in SCRIPT_SRC_REGEX.finditer(source):
        src_val = sc_match.group(1).strip()
        if not src_val or src_val in seen_scripts:
            continue
        seen_scripts.add(src_val)

        src_lower = src_val.lower()
        detected_lib = None
        for lib in known_libs:
            if lib in src_lower:
                detected_lib = lib.capitalize()
                break

        ver_match = VERSION_NUMBER_REGEX.search(src_val)
        version_hint = f"v{ver_match.group(0)}" if ver_match else None

        js_libraries.append(
            {
                "src": src_val,
                "library": detected_lib or "Harici Script",
                "version": version_hint,
            }
        )
        if len(js_libraries) >= 15:
            break

    total_artifacts = (
        len(comments)
        + len(hidden_inputs)
        + len(emails)
        + len(private_ips)
        + len(js_libraries)
    )

    return {
        "comments": comments,
        "hidden_inputs": hidden_inputs,
        "emails": emails,
        "private_ips": private_ips,
        "js_libraries": js_libraries,
        "total_artifacts": total_artifacts,
    }


# ---------------------------------------------------------------------------
# 3. ADIM ANA FONKSİYONU: HTTP GÜVENLİK BAŞLIKLARI, ÇEREZLER VE HTML KAZIYICI
# ---------------------------------------------------------------------------
def inspect_http_security(target_url: str) -> dict:
    """
    Hedefe tek bir GET isteği atarak:
    1) 8 koruyucu güvenlik başlığını,
    2) Sunucu bilgi sızıntısı başlıklarını,
    3) WAF/CDN varlığını,
    4) Set-Cookie güvenlik bayraklarını,
    5) HTML Kaynak Kod & CTF İstihbarat verilerini analiz eder.
    """
    response = requests.get(
        target_url,
        timeout=5,
        headers={"User-Agent": DEFAULT_USER_AGENT},
        allow_redirects=True,
    )

    resp_headers = response.headers

    security_headers = []
    present_count = 0

    for spec in SECURITY_HEADERS_SPEC:
        header_name = spec["header"]
        val = resp_headers.get(header_name)

        if val is not None:
            present_count += 1
            val_lower = val.lower()
            if header_name == "Content-Security-Policy" and (
                "'unsafe-inline'" in val_lower or "'unsafe-eval'" in val_lower
            ):
                status = "warning"
                badge = "UYARI (ESNEK POLİTİKA · +6 PUAN)"
            elif header_name == "Strict-Transport-Security" and "max-age=0" in val_lower:
                status = "warning"
                badge = "UYARI (MAX-AGE=0)"
            else:
                status = "safe"
                badge = "GÜVENLİ"
        else:
            if spec["critical"]:
                status = "missing"
                badge = "EKSİK"
            else:
                status = "warning"
                badge = "EKSİK (ÖNERİLEN)"

        security_headers.append(
            {
                "header": header_name,
                "short": spec["short"],
                "weight": spec["weight"],
                "description": spec["description"],
                "remediation": spec["remediation"],
                "present": val is not None,
                "value": val if val is not None else "Tanımlanmamış",
                "status": status,
                "badge": badge,
            }
        )

    disclosure_headers = []
    leak_count = 0

    for spec in DISCLOSURE_HEADERS_SPEC:
        header_name = spec["header"]
        val = resp_headers.get(header_name)
        eval_res = evaluate_server_header(header_name, val)
        if eval_res["leaked"]:
            leak_count += 1

        disclosure_headers.append(
            {
                "header": header_name,
                "description": spec["description"],
                "remediation": spec["remediation"],
                "leaked": eval_res["leaked"],
                "is_proxy_masked": eval_res["is_proxy_masked"],
                "value": eval_res["value"],
                "status": eval_res["status"],
                "badge": eval_res["badge"],
            }
        )

    cookie_keys = list(response.cookies.keys())
    set_cookie_raw = resp_headers.get("Set-Cookie", "")
    if set_cookie_raw:
        cookie_keys.append(set_cookie_raw)

    waf_cdn_list = detect_waf_cdn(dict(resp_headers), cookie_keys)
    cookie_audit = analyze_cookies(response)
    html_intel = scrape_html_intelligence(response.text)

    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
        "security_headers": security_headers,
        "present_count": present_count,
        "total_security_headers": len(SECURITY_HEADERS_SPEC),
        "disclosure_headers": disclosure_headers,
        "leak_count": leak_count,
        "waf_cdn": waf_cdn_list,
        "cookie_audit": cookie_audit,
        "html_intel": html_intel,
    }


# ---------------------------------------------------------------------------
# 4. ADIM FONKSİYONU: SSL/TLS SERTİFİKA VE KRİPTOGRAFİ DENETİMİ
# ---------------------------------------------------------------------------
def inspect_ssl_tls(hostname: str) -> dict:
    """
    Hedefin 443 portuna SSL soketi ile bağlanarak sertifika sağlayıcısını (Issuer),
    TLS protokol sürümünü, bitiş tarihini ve kalan gün sayısını hesaplar.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "Bilinmiyor"

        issuer_info = {}
        for rdn in cert.get("issuer", ()):
            for key, value in rdn:
                issuer_info[key] = value

        org = issuer_info.get("organizationName")
        cn = issuer_info.get("commonName")
        if org and cn and org != cn:
            issuer_str = f"{org} ({cn})"
        else:
            issuer_str = org or cn or "Bilinmeyen Sağlayıcı"

        not_after_raw = cert.get("notAfter")
        if not_after_raw:
            expiry_dt = datetime.strptime(
                not_after_raw, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            days_remaining = (expiry_dt - now_dt).days
            expiry_formatted = expiry_dt.strftime("%Y-%m-%d %H:%M UTC")
        else:
            days_remaining = -1
            expiry_formatted = "Okunamadı"

        if days_remaining < 0:
            status = "critical"
            badge = "KRİTİK RİSK (SÜRESİ GEÇMİŞ)"
        elif days_remaining < 30:
            status = "warning"
            badge = "YAKINDA DOLUYOR (<30 GÜN)"
        else:
            status = "safe"
            badge = "GEÇERLİ SERTİFİKA"

        return {
            "has_ssl": True,
            "issuer": issuer_str,
            "tls_version": tls_version,
            "expiry_date": expiry_formatted,
            "days_remaining": days_remaining,
            "status": status,
            "badge": badge,
            "detail": None,
        }

    except Exception as exc:
        return {
            "has_ssl": False,
            "issuer": "Sertifika Alınamadı / Yok",
            "tls_version": "Yok / Başarısız",
            "expiry_date": "Geçersiz",
            "days_remaining": None,
            "status": "critical",
            "badge": "KRİTİK RİSK (SSL YOK / GEÇERSİZ)",
            "detail": f"443 portu üzerinden geçerli bir SSL/TLS oturumu kurulamadı: {exc}",
        }


# ---------------------------------------------------------------------------
# 5. ADIM YARDIMCI FONKSİYONU: GERÇEK İÇERİK DOĞRULAYICI (FALSE-POSITIVE FİLTRESİ)
# ---------------------------------------------------------------------------
def is_valid_200_response(resp: requests.Response, validator: str, canary_lengths: list[int]) -> bool:
    """
    200 OK dönen bir yanıtın sahte (SPA fallback, özel 404 sayfası veya WAF engeli)
    olup olmadığını içerik tipi, imza ve kanarya yanıt boyutu ile doğrular.
    """
    content_type = (resp.headers.get("Content-Type") or "").lower()
    body_text = (resp.text or "")[:4096]
    body_lower = body_text.lower()
    body_len = len(resp.content or b"")

    for c_len in canary_lengths:
        if c_len > 0 and abs(body_len - c_len) <= 16:
            return False

    if "just a moment..." in body_lower or "cf-browser-verification" in body_lower or "attention required!" in body_lower:
        return False

    is_html = "text/html" in content_type or "<!doctype html" in body_lower or "<html" in body_lower

    if validator == "env":
        return (not is_html) and ("=" in body_text) and len(body_text.strip()) > 3
    if validator == "git":
        return (not is_html) and ("[core]" in body_lower or "[remote" in body_lower or "repositoryformatversion" in body_lower)
    if validator == "phpinfo":
        return "php version" in body_lower and "phpinfo()" in body_lower
    if validator == "wp_config":
        return (not is_html) and ("db_name" in body_lower or "db_password" in body_lower or "wp_" in body_lower)
    if validator == "ds_store":
        return (not is_html) and body_len > 32 and b"Bud1" in (resp.content or b"")[:32]
    if validator == "non_empty_code":
        return (not is_html) and body_len > 10
    if validator == "binary_archive":
        return (not is_html) and body_len > 128 and ("application/zip" in content_type or "application/octet-stream" in content_type or "application/x-" in content_type)
    if validator == "sql":
        return (not is_html) and ("create table" in body_lower or "insert into" in body_lower or "mysqldump" in body_lower or "postgresql" in body_lower)
    if validator == "log":
        return (not is_html) and ("[" in body_text or "error" in body_lower or "exception" in body_lower or "stack" in body_lower) and body_len > 20
    if validator == "server_status":
        return "apache server status" in body_lower or "server version:" in body_lower or "active connections" in body_lower
    if validator == "phpmyadmin":
        return "phpmyadmin" in body_lower
    if validator == "admin_html":
        return is_html and ("type=\"password\"" in body_lower or "type='password'" in body_lower or "login" in body_lower or "admin" in body_lower)
    if validator == "openapi_json":
        return (not is_html) and ("\"openapi\"" in body_lower or "\"swagger\"" in body_lower)
    if validator == "api_docs":
        return "swagger-ui" in body_lower or "redoc" in body_lower or "\"openapi\"" in body_lower
    if validator == "graphql":
        return (not is_html) and ("\"data\"" in body_lower or "\"errors\"" in body_lower or "graphql" in body_lower)
    if validator == "json_api":
        return "application/json" in content_type and body_len > 2
    if validator == "package_json":
        return "application/json" in content_type and ("\"name\"" in body_lower and ("\"version\"" in body_lower or "\"dependencies\"" in body_lower))
    if validator == "actuator":
        return "application/json" in content_type and "\"status\"" in body_lower
    if validator == "robots":
        return (not is_html) and ("user-agent" in body_lower or "disallow" in body_lower or "allow" in body_lower or "sitemap" in body_lower)
    if validator == "xml":
        return ("xml" in content_type or body_lower.lstrip().startswith("<?xml")) and ("<urlset" in body_lower or "<sitemapindex" in body_lower or "<cross-domain-policy" in body_lower)
    if validator == "security_txt":
        return (not is_html) and ("contact:" in body_lower)
    if validator == "plain_text":
        return "text/plain" in content_type and (not is_html) and body_len > 10

    return True


def is_genuine_403_origin(
    resp: requests.Response,
    canary_statuses: set[int],
    canary_403_lengths: list[int],
) -> bool:
    """Sahte/WAF kaynaklı 403 Forbidden yanıtlarını eler."""
    if 403 in canary_statuses:
        return False

    lower_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    server_hdr = lower_headers.get("server", "")
    body_lower = (resp.text or "")[:2048].lower()
    body_len = len(resp.content or b"")

    for c_len in canary_403_lengths:
        if abs(body_len - c_len) <= 24:
            return False

    if (
        "cf-mitigated" in lower_headers
        or "cf-ray" in lower_headers
        or "x-amz-cf-id" in lower_headers
        or "x-akamai-transformed" in lower_headers
        or "x-sucuri-id" in lower_headers
        or "x-iinfo" in lower_headers
        or any(p in server_hdr for p in KNOWN_PROXY_SERVER_NAMES)
    ):
        return False

    waf_block_phrases = (
        "attention required!",
        "cloudflare",
        "ray id:",
        "access denied",
        "reference #",
        "request blocked",
        "generated by cloudfront",
        "sucuri website firewall",
        "incapsula incident id",
    )
    if any(phrase in body_lower for phrase in waf_block_phrases):
        return False

    return True


# ---------------------------------------------------------------------------
# 5. ADIM FONKSİYONU: PARALEL DİZİN VE DOSYA TARAMASI (KANARYA KALİBRASYONLU)
# ---------------------------------------------------------------------------
def enumerate_directories(base_url: str) -> dict:
    """
    Önce var olmayan rastgele iki kanarya (canary) uç noktaya istek atarak sunucunun/WAF'ın
    404/403/200 davranışını kalibre eder. Ardından 30 kritik hedefi ThreadPoolExecutor(max_workers=10)
    ile paralel tarar ve sahte 403 / sahte 200 yanıtlarını filtreler.
    """
    clean_base = base_url.rstrip("/")
    token = uuid.uuid4().hex[:10]
    canary_paths = [f"/__secheck_canary_{token}", f"/.env_canary_{token}"]

    canary_statuses: set[int] = set()
    canary_200_lengths: list[int] = []
    canary_403_lengths: list[int] = []

    for c_path in canary_paths:
        try:
            c_resp = requests.get(
                f"{clean_base}{c_path}",
                timeout=2,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=False,
            )
            canary_statuses.add(c_resp.status_code)
            if c_resp.status_code == 200:
                canary_200_lengths.append(len(c_resp.content or b""))
            elif c_resp.status_code == 403:
                canary_403_lengths.append(len(c_resp.content or b""))
        except requests.exceptions.RequestException:
            pass

    def check_single_target(spec: dict) -> dict | None:
        url = f"{clean_base}{spec['path']}"
        try:
            resp = requests.get(
                url,
                timeout=2,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=False,
            )
            code = resp.status_code

            if code == 200:
                if not is_valid_200_response(resp, spec.get("validator", ""), canary_200_lengths):
                    return None

                if spec["severity_on_200"] == "safe":
                    status = "safe"
                    badge = "200 OK · STANDART DOSYA"
                elif spec["severity_on_200"] == "warning":
                    status = "warning"
                    badge = "200 OK · AÇIK API ŞEMASI"
                else:
                    status = "critical"
                    badge = "200 OK · AÇIK UÇ NOKTA"

                disallows = []
                if spec["path"] == "/robots.txt" and resp.text:
                    for line in resp.text.splitlines():
                        stripped = line.strip()
                        if stripped.lower().startswith("disallow:"):
                            rule_val = stripped.split(":", 1)[1].strip()
                            if rule_val:
                                disallows.append(rule_val)

                return {
                    "path": spec["path"],
                    "url": url,
                    "category": spec["category"],
                    "status_code": 200,
                    "status": status,
                    "badge": badge,
                    "disallows": disallows[:25],
                }

            if code == 403:
                if not is_genuine_403_origin(resp, canary_statuses, canary_403_lengths):
                    return None

                return {
                    "path": spec["path"],
                    "url": url,
                    "category": spec["category"],
                    "status_code": 403,
                    "status": "warning",
                    "badge": "403 FORBIDDEN · DİZİN ERİŞİMİ KISITLI",
                    "disallows": [],
                }

        except requests.exceptions.RequestException:
            return None

        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        raw_results = list(executor.map(check_single_target, DIRECTORY_TARGETS_SPEC))

    findings = [item for item in raw_results if item is not None]
    robots_disallow = []
    for item in findings:
        if item["path"] == "/robots.txt" and item["disallows"]:
            robots_disallow = item["disallows"]
            break

    return {
        "total_scanned": len(DIRECTORY_TARGETS_SPEC),
        "found_count": len(findings),
        "findings": findings,
        "robots_disallow": robots_disallow,
    }


# ---------------------------------------------------------------------------
# 6. ADIM FONKSİYONU: AĞIRLIKLI GÜVENLİK SKORU ALGORİTMASI VE ÇÖZÜM REHBERİ (V3.0)
# ---------------------------------------------------------------------------
def calculate_security_score_and_remediation(
    ssl_info: dict,
    http_audit: dict,
    dir_scan: dict,
    port_scan: dict,
    shodan_intel: dict,
    dns_security: dict,
) -> dict:
    """
    AEGIS V3.0 Ağırlıklı Güvenlik Skoru Algoritması (0 - 100 Puan):
    - Kategori 1: Kriptografi & SSL (Maksimum 25 Puan)
    - Kategori 2: HTTP Güvenlik Başlıkları (Maksimum 45 Puan, esnek CSP +6 puan)
    - Kategori 3: Saldırı Yüzeyi, Port, CVE & İfşa Kontrolü (Maksimum 20 Puan + Kritik Ceza):
        * Sürüm sızdıran başlıklar: -5 puan
        * Eksik çerez bayrakları: maksimum -4 puan
        * Yüksek riskli açık yönetim/veritabanı portları (21, 22, 23, 3306, 5432, 6379): port başına -5 puan
        * Shodan InternetDB üzerinde kayıtlı CVE zafiyetleri: CVE başına -5 puan
        * Açık yönetim/API uç noktaları: -5 puan
        * Kritik dosya/yedek ifşası: Kategori 3 sıfırlanır + genel skora -15 ceza
    - Kategori 4: Standartlar, WAF & E-Posta/DNS Savunması (Maksimum 10 Puan):
        * WAF/CDN Koruması: +4 puan
        * RFC 9116 /.well-known/security.txt: +2 puan
        * SPF Kaydı (-all ise +2 puan, ~all ise +1 puan)
        * DMARC Politikası (reject/quarantine ise +2 puan, none ise +1 puan)
    """
    remediations = []

    # =========================================================================
    # KATEGORİ 1: Kriptografi & SSL (Maksimum 25 Puan)
    # =========================================================================
    ssl_valid = (
        ssl_info.get("has_ssl")
        and ssl_info.get("days_remaining") is not None
        and ssl_info.get("days_remaining") >= 0
    )
    if not ssl_valid:
        cat1_score = 0
        remediations.append(
            {
                "severity": "critical",
                "badge": "KRİTİK ALARM · SSL/TLS",
                "title": "Geçerli bir SSL/TLS Sertifikası Bulunamadı veya Süresi Dolmuş",
                "finding": ssl_info.get("detail")
                or "443 portunda geçerli bir sertifika doğrulanamadı.",
                "solution": "Let's Encrypt veya kurumsal bir CA üzerinden geçerli bir X.509 sertifikası kurun, tüm HTTP trafiğini 301 ile HTTPS'e yönlendirin ve TLSv1.3 protokolünü etkinleştirin.",
            }
        )
    else:
        cat1_score = 15
        tls_ver = (ssl_info.get("tls_version") or "").upper()
        if "TLSV1.3" in tls_ver:
            cat1_score += 10
        elif "TLSV1.2" in tls_ver:
            cat1_score += 5
            remediations.append(
                {
                    "severity": "low",
                    "badge": "İYİLEŞTİRME · KRİPTOGRAFİ",
                    "title": f"TLS Protokolü TLSv1.3'e Yükseltilebilir (Mevcut: {ssl_info.get('tls_version')})",
                    "finding": "Sunucu TLSv1.2 kullanıyor; modern şifreleme kümeleri ve daha düşük el sıkışma gecikmesi için TLSv1.3 önerilir.",
                    "solution": "ssl_protocols TLSv1.2 TLSv1.3; # Nginx yapılandırması",
                }
            )
        else:
            remediations.append(
                {
                    "severity": "high",
                    "badge": "YÜKSEK RİSK · ESKİ TLS",
                    "title": f"Eski TLS Sürümü Tespit Edildi ({ssl_info.get('tls_version')})",
                    "finding": "TLS 1.0/1.1 sürümleri bilinen kriptografik zafiyetler barındırır.",
                    "solution": "TLS 1.0 ve 1.1 protokollerini devre dışı bırakıp yalnızca TLSv1.2 ve TLSv1.3'e izin verin.",
                }
            )

        if ssl_info.get("days_remaining", 999) < 30:
            remediations.append(
                {
                    "severity": "medium",
                    "badge": "UYARI · SERTİFİKA SÜRESİ",
                    "title": f"SSL Sertifikasının Dolmasına {ssl_info.get('days_remaining')} Gün Kaldı",
                    "finding": f"Sertifika bitiş tarihi: {ssl_info.get('expiry_date')}.",
                    "solution": "Kesinti yaşamamak için ACME / Certbot otomatik yenileme zamanlayıcısını kontrol edin.",
                }
            )

    # =========================================================================
    # KATEGORİ 2: HTTP Güvenlik Başlıkları (Maksimum 45 Puan)
    # =========================================================================
    header_weights = {
        "Content-Security-Policy": 12.0,
        "Strict-Transport-Security": 10.0,
        "X-Frame-Options": 6.0,
        "X-Content-Type-Options": 6.0,
        "Referrer-Policy": 4.0,
        "Permissions-Policy": 4.0,
        "Cross-Origin-Opener-Policy": 1.5,
        "Cross-Origin-Resource-Policy": 1.5,
    }
    cat2_score = 0.0
    for item in http_audit.get("security_headers", []):
        h_name = item["header"]
        if item["present"]:
            if h_name == "Content-Security-Policy" and item.get("status") == "warning":
                cat2_score += 6.0
                remediations.append(
                    {
                        "severity": "medium",
                        "badge": "ESNEK CSP · -6 PUAN",
                        "title": "CSP aktif ancak 'unsafe-inline' veya 'unsafe-eval' içerdiği için XSS koruması zayıflıyor (-6 Puan)",
                        "finding": f"Mevcut politika: {item['value'][:140]}",
                        "solution": "Content-Security-Policy içinde 'unsafe-inline' ve 'unsafe-eval' direktiflerini kaldırıp nonce veya hash tabanlı script yetkilendirmesine geçin.",
                    }
                )
            else:
                cat2_score += header_weights.get(h_name, 0.0)
        else:
            is_crit = h_name in (
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
            )
            remediations.append(
                {
                    "severity": "high" if is_crit else "medium",
                    "badge": f"EKSİK BAŞLIK · -{format_num(header_weights.get(h_name, 0))} PUAN",
                    "title": f"{h_name} ({item['short']}) Yanıt Başlığı Tanımlanmamış",
                    "finding": item["description"],
                    "solution": f"add_header {item['remediation']} always;",
                }
            )

    # =========================================================================
    # KATEGORİ 3: Saldırı Yüzeyi, Port, CVE & İfşa Kontrolü (Maksimum 20 Puan)
    # =========================================================================
    cat3_score = 20.0
    critical_penalty = 0
    critical_exposure_paths = []
    admin_api_exposure_paths = []
    forbidden_paths = []

    for finding in dir_scan.get("findings", []):
        cat = finding["category"]
        code = finding["status_code"]

        if code == 200:
            if cat in (
                "KRİTİK SIZINTI - Hassas Dosyalar",
                "YÜKSEK RİSK - Yedek & Log",
            ):
                critical_exposure_paths.append(finding)
            elif cat in ("YÖNETİM PANELLERİ - Admin", "API & GELİŞTİRİCİ") and finding.get("status") == "critical":
                admin_api_exposure_paths.append(finding)
        elif code == 403:
            forbidden_paths.append(finding)

    # 3A. Bilgi Sızıntısı Başlıkları (-5 puan)
    leaked_headers = [
        d for d in http_audit.get("disclosure_headers", []) if d["leaked"]
    ]
    if leaked_headers:
        cat3_score -= 5
        for lh in leaked_headers:
            remediations.append(
                {
                    "severity": "medium",
                    "badge": "SÜRÜM İFŞASI · -5 PUAN",
                    "title": f"{lh['header']} Başlığı Yazılım Sürümü Sızdırıyor ({lh['value']})",
                    "finding": f"Yanıt başlığında '{lh['value']}' bilgisi açıkça dönüyor. Saldırganların CVE eşleştirmesi yapmasını kolaylaştırır.",
                    "solution": lh["remediation"],
                }
            )

    # 3B. Çerez (Cookie) Güvenliği Kesintisi (Maksimum -4 puan)
    cookie_audit = http_audit.get("cookie_audit") or {}
    cookie_penalty = float(cookie_audit.get("penalty", 0))
    if cookie_penalty > 0:
        cat3_score -= cookie_penalty
        weak_cookie_names = [
            f"{c['name']} ({', '.join(c['missing_flags'])})"
            for c in cookie_audit.get("cookies", [])
            if c.get("missing_flags")
        ]
        remediations.append(
            {
                "severity": "medium",
                "badge": f"ÇEREZ GÜVENLİĞİ · -{format_num(cookie_penalty)} PUAN",
                "title": "Oturum / Uygulama Çerezlerinde Güvenlik Bayrakları Eksik",
                "finding": f"Eksik bayrak tespit edilen çerezler: {', '.join(weak_cookie_names)}.",
                "solution": "Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Strict (veya Lax) bayraklarını tüm çerezlerde zorunlu kılın.",
            }
        )

    # 3C. AEGIS V3.0 Geliştirme 2: Yüksek Riskli Açık Yönetim / Veritabanı Portları (Port başına -5 puan)
    for hp in port_scan.get("high_risk_ports", []):
        cat3_score -= 5.0
        remediations.append(
            {
                "severity": "high",
                "badge": f"AÇIK PORT ({hp['port']}/{hp['service']}) · -5 PUAN",
                "title": f"Dış Dünyaya Açık Tehlikeli Yönetim / Veritabanı Portu: TCP {hp['port']} ({hp['service']})",
                "finding": f"TCP {hp['port']} ({hp['desc']}) portu dış ağdan doğrudan bağlantıya açık. Yakalanan Banner: {hp['banner']}",
                "solution": f"ufw deny {hp['port']}/tcp  # veya güvenlik duvarında (Firewall / Security Group) {hp['port']} portunu yalnızca VPN/Localhost erişimine kısıtlayın.",
            }
        )

    # 3D. AEGIS V3.0 Geliştirme 3: Shodan InternetDB CVE Zafiyetleri (CVE başına -5 puan)
    vulns_list = shodan_intel.get("vulns") or []
    if vulns_list:
        cve_deduction = min(20.0, float(len(vulns_list) * 5))
        cat3_score -= cve_deduction
        cve_preview = ", ".join(vulns_list[:8])
        if len(vulns_list) > 8:
            cve_preview += f" (+{len(vulns_list) - 8} diğer)"
        remediations.append(
            {
                "severity": "critical",
                "badge": f"SHODAN CVE ({len(vulns_list)} ZAFİYET) · -{format_num(cve_deduction)} PUAN",
                "title": f"Hedef IP Üzerinde Bilinen {len(vulns_list)} Adet CVE Güvenlik Zafiyeti Tespit Edildi",
                "finding": f"Shodan InternetDB kayıtlarında doğrulanmış CVE kodları: {cve_preview}.",
                "solution": "Sunucu üzerindeki web sunucusu, OpenSSH ve işletim sistemi paketlerini güvenlik yamalarıyla (apt upgrade / dnf update) derhal güncelleyin.",
            }
        )

    # 3E. Açık Yönetim Panelleri / API Uç Noktaları (-5 puan)
    for exp in admin_api_exposure_paths:
        cat3_score -= 5
        remediations.append(
            {
                "severity": "high",
                "badge": "AÇIK UÇ NOKTA · -5 PUAN",
                "title": f"Dış Ağa Açık Yönetim / API Uç Noktası: {exp['path']}",
                "finding": f"[{exp['category']}] kategorisindeki '{exp['url']}' adresi doğrudan erişilebilir (200 OK) durumda.",
                "solution": "Yönetim panellerini ve API şemalarını VPN, Zero-Trust erişim politikası veya IP kısıtlaması (Allowlist) arkasına alın.",
            }
        )

    if critical_exposure_paths:
        cat3_score = 0.0
        critical_penalty = 15
        for crit in critical_exposure_paths:
            remediations.append(
                {
                    "severity": "critical",
                    "badge": "KRİTİK ALARM · -15 CEZA",
                    "title": f"Hassas Dosya / Yedek İfşası Tespit Edildi: {crit['path']}",
                    "finding": f"[{crit['category']}] altındaki '{crit['url']}' adresi doğrulanmış 200 OK yanıtı ile dış dünyaya açık!",
                    "solution": "location ~ /\\.(env|git|DS_Store) { deny all; return 404; } # Dosyayı derhal genel dizinden kaldırın ve anahtarları yenileyin.",
                }
            )
    else:
        cat3_score = max(0.0, cat3_score)

    if forbidden_paths:
        paths_str = ", ".join(f["path"] for f in forbidden_paths)
        remediations.append(
            {
                "severity": "low",
                "badge": "403 FORBIDDEN · BİLGİ",
                "title": f"Kaynak Sunucuda Erişimi Kısıtlanmış Dizinler: {paths_str}",
                "finding": "Kaynak sunucu bu dizinler için doğrudan 403 Forbidden döndürüyor.",
                "solution": "Dizin varlığını gizlemek isterseniz web sunucusunda 403 yerine 404 yanıtı döndürecek şekilde yapılandırabilirsiniz.",
            }
        )

    # =========================================================================
    # KATEGORİ 4: Standartlar, WAF & E-Posta/DNS Savunması (Maksimum 10 Puan)
    # - WAF/CDN: +4 Puan
    # - /.well-known/security.txt: +2 Puan
    # - SPF (-all: +2 Puan, ~all: +1 Puan)
    # - DMARC (reject/quarantine: +2 Puan, none: +1 Puan)
    # =========================================================================
    cat4_score = 0.0
    has_waf = len(http_audit.get("waf_cdn", [])) > 0
    has_security_txt = any(
        f["path"] == "/.well-known/security.txt" and f["status_code"] == 200
        for f in dir_scan.get("findings", [])
    )

    if has_waf:
        cat4_score += 4.0
    else:
        remediations.append(
            {
                "severity": "low",
                "badge": "SAVUNMA DERİNLİĞİ · -4 PUAN",
                "title": "WAF / Edge CDN Koruma Katmanı Tespit Edilemedi",
                "finding": "Yanıt başlıklarında bilinen bir WAF/CDN (Cloudflare, Akamai, CloudFront vb.) imzası görülmedi.",
                "solution": "DDoS ve uygulama katmanı (L7) saldırılarını süzmek için Cloudflare, AWS WAF veya Akamai gibi bir Edge koruma katmanı kullanın.",
            }
        )

    if has_security_txt or dir_scan.get("skipped"):
        cat4_score += 2.0
    else:
        remediations.append(
            {
                "severity": "low",
                "badge": "RFC 9116 · -2 PUAN",
                "title": "/.well-known/security.txt Dosyası Tanımlanmamış",
                "finding": "Güvenlik araştırmacılarının sorumlu bildirim (Responsible Disclosure) yapabileceği standart iletişim dosyası bulunamadı.",
                "solution": "Contact: mailto:security@alanadiniz.com ve Expires alanlarını içeren /.well-known/security.txt dosyasını yayınlayın.",
            }
        )

    # SPF Puanlama ve Çözüm Önerisi
    spf_info = (dns_security or {}).get("spf") or {}
    spf_mode = spf_info.get("mode", "missing")
    if spf_mode in ("hardfail", "redirect_or_custom"):
        cat4_score += 2.0
    elif spf_mode == "softfail":
        cat4_score += 1.0
        remediations.append(
            {
                "severity": "low",
                "badge": "SPF SOFTFAIL (~all) · -1 PUAN",
                "title": "SPF Kaydında Esnek Politika (~all) Kullanılıyor",
                "finding": f"Mevcut SPF kaydı: {spf_info.get('record')}",
                "solution": "Yetkisiz e-posta gönderimlerini kesin olarak engellemek için SPF kaydınızın sonundaki '~all' ifadesini '-all' (Hardfail) olarak güncelleyin.",
            }
        )
    else:
        remediations.append(
            {
                "severity": "medium",
                "badge": "E-POSTA SPOOFING · -2 PUAN",
                "title": "Alan Adında Geçerli Bir SPF Kaydı Bulunamadı",
                "finding": spf_info.get("desc") or "SPF TXT kaydı eksik; saldırganlar alan adınızı taklit ederek sahte e-posta gönderebilir.",
                "solution": f"{dns_security.get('root_domain', 'domain.com')}. IN TXT \"v=spf1 include:_spf.google.com -all\"",
            }
        )

    # DMARC Puanlama ve Çözüm Önerisi
    dmarc_info = (dns_security or {}).get("dmarc") or {}
    dmarc_policy = dmarc_info.get("policy", "Yok")
    if dmarc_policy in ("reject", "quarantine"):
        cat4_score += 2.0
    elif dmarc_policy == "none":
        cat4_score += 1.0
        remediations.append(
            {
                "severity": "low",
                "badge": "DMARC İZLEME (p=none) · -1 PUAN",
                "title": "DMARC Politikası Yalnızca İzleme Modunda (p=none)",
                "finding": f"Mevcut DMARC kaydı: {dmarc_info.get('record')}",
                "solution": f"_dmarc.{dns_security.get('root_domain', 'domain.com')}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{dns_security.get('root_domain', 'domain.com')}\"",
            }
        )
    else:
        remediations.append(
            {
                "severity": "medium",
                "badge": "DMARC EKSİK · -2 PUAN",
                "title": "Alan Adında DMARC Politikası (_dmarc) Tanımlanmamış",
                "finding": dmarc_info.get("desc") or "DMARC kaydı eksik olduğu için SPF/DKIM ihlalleri alıcı posta sunucuları tarafından denetlenemiyor.",
                "solution": f"_dmarc.{dns_security.get('root_domain', 'domain.com')}. IN TXT \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;\"",
            }
        )

    # =========================================================================
    # GENEL TOPLAM SKOR VE HARF NOTU SKALASI (0 - 100)
    # =========================================================================
    raw_total = cat1_score + cat2_score + cat3_score + cat4_score - critical_penalty
    total_score = format_num(max(0.0, min(100.0, raw_total)))

    if total_score >= 90:
        grade = "A+"
        grade_color = "emerald"
        grade_label = "Optimum Güvenlik Duruşu"
    elif total_score >= 80:
        grade = "A"
        grade_color = "emerald"
        grade_label = "Güçlü Kurumsal Koruma"
    elif total_score >= 70:
        grade = "B"
        grade_color = "blue"
        grade_label = "İyi Seviye · Başlık Sıkılaştırması Önerilir"
    elif total_score >= 60:
        grade = "C"
        grade_color = "amber"
        grade_label = "Orta Seviye · Eksik Politikalar Mevcut"
    elif total_score >= 50:
        grade = "D"
        grade_color = "amber"
        grade_label = "Zayıf Koruma · Yüksek Yapılandırma Eksikleri"
    else:
        grade = "F"
        grade_color = "rose"
        grade_label = "Kritik Risk · Acil Sıkılaştırma Gerekli"

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    remediations.sort(key=lambda r: severity_order.get(r["severity"], 4))

    categories = [
        {
            "id": "crypto",
            "name": "Kriptografi & TLS Altyapısı",
            "score": format_num(cat1_score),
            "max_score": 25,
            "percent": int(round((cat1_score / 25.0) * 100)),
            "desc": "Sertifika geçerliliği (+15) ve TLS protokol sürümü (+10)",
        },
        {
            "id": "headers",
            "name": "HTTP Güvenlik Politikaları",
            "score": format_num(cat2_score),
            "max_score": 45,
            "percent": int(round((cat2_score / 45.0) * 100)),
            "desc": "CSP (12/6), HSTS (10), XFO (6), XCTO (6), RP (4), PP (4), COOP/CORP (3)",
        },
        {
            "id": "surface",
            "name": "Saldırı Yüzeyi, Port & CVE",
            "score": format_num(cat3_score),
            "max_score": 20,
            "percent": int(round((cat3_score / 20.0) * 100)),
            "desc": "Açık portlar, Shodan CVE, çerez bayrakları, sürüm gizliliği ve uç noktalar",
        },
        {
            "id": "defense",
            "name": "WAF, DNS & E-Posta Savunması",
            "score": format_num(cat4_score),
            "max_score": 10,
            "percent": int(round((cat4_score / 10.0) * 100)),
            "desc": "WAF/CDN (+4), SPF (+2), DMARC (+2) ve security.txt (+2)",
        },
    ]

    return {
        "total_score": total_score,
        "grade": grade,
        "grade_color": grade_color,
        "grade_label": grade_label,
        "critical_penalty": critical_penalty,
        "categories": categories,
        "remediations": remediations,
    }


# ---------------------------------------------------------------------------
# FASTAPI ENDPOINT'LERİ (ANA SAYFA, ANALİZ MOTORU VE TARAMA GEÇMİŞİ)
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Ana sayfa görünümünü son 10 tarama geçmişiyle birlikte sunar."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "target_intel": None,
            "http_audit": None,
            "ssl_info": None,
            "dir_scan": None,
            "port_scan": None,
            "shodan_intel": None,
            "dns_security": None,
            "score_report": None,
            "full_report_json": None,
            "scan_history": get_recent_scans(10),
            "scan_mode": "active",
            "error": None,
            "url": "",
        },
    )


@app.post("/history/clear")
async def clear_history_endpoint(request: Request):
    """SQLite tarama geçmişini temizler ve JSON veya yönlendirme yanıtı döner."""
    clear_scan_history()
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse({"status": "cleared"})
    return RedirectResponse(url="/", status_code=303)


@app.api_route("/analyze", methods=["GET", "POST"], response_class=HTMLResponse)
async def analyze(request: Request, url: str | None = None, scan_mode: str | None = None):
    """
    Hedef URL için Aegis V3.0 denetim adımlarını çalıştırır ve SQLite'a kaydeder.
    scan_mode == 'passive' (Güvenli Mod) seçildiğinde:
    - 30'lu dizin taraması (enumerate_directories) ve 14'lü aktif TCP port taraması (scan_ports_and_banners) ÇALIŞTIRILMAZ.
    - Hedefe yalnızca 1 adet standart HTTP GET isteği atılır (HTTP Başlıkları, SSL, Çerezler, HTML Analizi, DNS SPF/DMARC ve pasif Shodan InternetDB çalışır).
    """
    if request.method == "POST":
        body_bytes = await request.body()
        parsed_body = parse_qs(body_bytes.decode("utf-8", errors="ignore"))
        if not url:
            url = parsed_body.get("url", [None])[0]
        if not scan_mode:
            scan_mode = parsed_body.get("scan_mode", ["active"])[0]

    normalized_mode = "passive" if (scan_mode or "").lower() == "passive" else "active"
    is_active_mode = normalized_mode == "active"

    target_intel = None
    http_audit = None
    ssl_info = None
    dir_scan = None
    port_scan = None
    shodan_intel = None
    dns_security = None
    score_report = None
    full_report_json = None
    error = None

    try:
        target_intel = parse_and_resolve_target(url or "")
        ssl_info = inspect_ssl_tls(target_intel["hostname"])
        http_audit = inspect_http_security(target_intel["normalized_url"])

        # Kök alan adı yönlendirmesi (örn. domain.com -> www.domain.com) varsa kanonik kök URL'yi kullan
        final_parsed = urlparse(http_audit["final_url"])
        canonical_base = (
            f"{final_parsed.scheme}://{final_parsed.netloc}"
            if final_parsed.netloc
            else target_intel["base_url"]
        )

        if is_active_mode:
            # Tam Denetim Modu: Dizin taraması, 14 TCP Port & Banner taraması, Shodan InternetDB ve DNS/SPF/DMARC paralel çalışır
            with ThreadPoolExecutor(max_workers=4) as module_exec:
                fut_dir = module_exec.submit(enumerate_directories, canonical_base)
                fut_ports = module_exec.submit(
                    scan_ports_and_banners, target_intel["ipv4"], target_intel["hostname"]
                )
                fut_shodan = module_exec.submit(query_shodan_internetdb, target_intel["ipv4"])
                fut_dns = module_exec.submit(inspect_dns_email_security, target_intel["hostname"])

                dir_scan = fut_dir.result()
                port_scan = fut_ports.result()
                shodan_intel = fut_shodan.result()
                dns_security = fut_dns.result()
        else:
            # Pasif / Güvenli Mod: Hedefe ek paket gönderilmez; yalnızca pasif Shodan InternetDB ve Google DoH DNS çalışır
            with ThreadPoolExecutor(max_workers=2) as passive_exec:
                fut_shodan = passive_exec.submit(query_shodan_internetdb, target_intel["ipv4"])
                fut_dns = passive_exec.submit(inspect_dns_email_security, target_intel["hostname"])
                shodan_intel = fut_shodan.result()
                dns_security = fut_dns.result()

            dir_scan = {
                "skipped": True,
                "total_scanned": 0,
                "found_count": 0,
                "findings": [],
                "robots_disallow": [],
            }
            port_scan = {
                "skipped": True,
                "total_scanned": 0,
                "open_count": len(shodan_intel.get("shodan_ports") or []),
                "high_risk_count": 0,
                "open_ports": [],
                "high_risk_ports": [],
                "all_ports": [],
            }

        score_report = calculate_security_score_and_remediation(
            ssl_info=ssl_info,
            http_audit=http_audit,
            dir_scan=dir_scan,
            port_scan=port_scan,
            shodan_intel=shodan_intel,
            dns_security=dns_security,
        )

        # Başarılı analizi SQLite aegis_history.db veritabanına kaydet
        save_scan_history(
            hostname=target_intel["hostname"],
            ipv4=target_intel["ipv4"],
            total_score=score_report["total_score"],
            grade=score_report["grade"],
            open_ports_count=port_scan["open_count"],
            cve_count=shodan_intel["cve_count"],
        )

        full_report_json = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine": "Secheck",
            "scan_mode": normalized_mode,
            "target_intel": target_intel,
            "score_report": score_report,
            "ssl_info": ssl_info,
            "http_audit": http_audit,
            "port_scan": port_scan,
            "shodan_intel": shodan_intel,
            "dns_security": dns_security,
            "dir_scan": dir_scan,
        }
    except socket.gaierror:
        error = (
            f"DNS Çözümleme Hatası: '{url}' alan adı çözümlenemedi. "
            "Alan adının doğru yazıldığından ve aktif bir A kaydına sahip olduğundan emin olun."
        )
    except requests.exceptions.Timeout:
        error = "Bağlantı Zaman Aşımı: Hedef sunucu 5 saniye içinde yanıt vermedi."
    except requests.exceptions.RequestException as exc:
        error = f"HTTP İletişim Hatası: Hedef sunucuya ulaşılamadı ({exc})."
    except ValueError as exc:
        error = str(exc)
    except Exception as exc:
        error = f"Denetim Hatası: Hedef incelenirken beklenmeyen bir durum oluştu ({exc})."

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "target_intel": target_intel,
            "http_audit": http_audit,
            "ssl_info": ssl_info,
            "dir_scan": dir_scan,
            "port_scan": port_scan,
            "shodan_intel": shodan_intel,
            "dns_security": dns_security,
            "score_report": score_report,
            "full_report_json": full_report_json,
            "scan_history": get_recent_scans(10),
            "scan_mode": normalized_mode,
            "error": error,
            "url": (url or "").strip(),
        },
    )
