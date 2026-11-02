#!/usr/bin/env python3
"""
============================================================
OSINT HUNTER v2.0 - Open Source Intelligence
============================================================
Menu interaktif dengan tampilan modern.

Fitur:
  1. IP Geolocation Lookup
  2. DNS Lookup
  3. WHOIS Lookup
  4. HTTP Header Grabber
  5. Subdomain Brute-force
  6. Port Scanner
  7. Username Availability
  8. Jalankan SEMUA modul (otomatis)
  9. Modul Lanjutan (Advanced OSINT)
  10. Keluar

PERINGATAN HUKUM & ETIKA:
  Gunakan HANYA untuk pendidikan, riset keamanan, dan pengujian
  pada aset yang Anda miliki atau memiliki izin tertulis.

Versi : 2.0
============================================================
"""

import ipaddress
import json
import os
import socket
import sys
import urllib.request
from datetime import datetime

from ui import (
    C, BOX, ICON, c, get_hasil_path,
    header, section, menu_item, line,
    success, error, info, warning, result, box,
    prompt, confirm, footer, supports_color, loading
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import osint_advanced
    HAS_ADVANCED = True
except ImportError:
    HAS_ADVANCED = False



def validasi_domain(domain):
    return domain and "." in domain and " " not in domain


def validasi_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def simpan_hasil(nama_file, data):
    try:
        path = get_hasil_path(nama_file)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False, default=str)
        success("Hasil disimpan ke: {}".format(path))
        return True
    except Exception as e:
        error("Gagal menyimpan hasil: {}".format(e))
        return False


def tanya_simpan(target):
    jawab = prompt("Simpan hasil ke file JSON? (y/n): ")
    if jawab == "y":
        aman = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in target)
        return "hasil_{}.json".format(aman)
    return None


def ip_geolocation(target, simpan_file=None):
    section("IP GEOLOCATION LOOKUP", icon="geo")
    info("Target: {}".format(target))
    hasil = {"target": target, "waktu": datetime.now().isoformat()}

    if not validasi_ip(target):
        try:
            target_ip = socket.gethostbyname(target)
            info("Domain {} direkonsi menjadi {}".format(target, target_ip))
            hasil["domain"] = target
            hasil["ip"] = target_ip
            target = target_ip
        except socket.gaierror as e:
            error("Tidak dapat merekonsi domain: {}".format(e))
            return

    url = "http://ip-api.com/json/{}".format(target)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Toolkit/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("status") == "fail":
            error("Gagal mendapatkan data geolocation: {}".format(data.get("message")))
            return

        fields = [
            ("country", "Negara"),
            ("regionName", "Wilayah"),
            ("city", "Kota"),
            ("zip", "Kode Pos"),
            ("lat", "Latitude"),
            ("lon", "Longitude"),
            ("timezone", "Zona Waktu"),
            ("isp", "ISP"),
            ("org", "Organisasi"),
            ("as", "AS"),
            ("query", "IP"),
        ]
        for fld, label in fields:
            if fld in data:
                hasil[fld] = data[fld]
                result(label, data[fld])

    except Exception as e:
        error("Error saat geolocation lookup: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


def dns_lookup(domain, simpan_file=None):
    section("DNS LOOKUP", icon="dns")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "records": {}}
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            if rtype in ("A", "AAAA"):
                infolist = socket.getaddrinfo(domain, None)
                values = []
                for res in infolist:
                    addr = res[4][0]
                    if rtype == "A" and ":" not in addr:
                        values.append(addr)
                    elif rtype == "AAAA" and ":" in addr:
                        values.append(addr)
                hasil["records"][rtype] = sorted(set(values))
                val = ", ".join(hasil["records"][rtype]) if values else "-"
                result(rtype, val)
            else:
                if HAS_REQUESTS:
                    doh_url = "https://dns.google/resolve"
                    params = {"name": domain, "type": rtype}
                    try:
                        r = requests.get(doh_url, params=params, timeout=15)
                        data = r.json()
                        answers = data.get("Answer", [])
                        values = [ans.get("data", "") for ans in answers]
                        hasil["records"][rtype] = values
                        val = ", ".join(values) if values else "-"
                        result(rtype, val)
                    except Exception:
                        hasil["records"][rtype] = []
                        result(rtype, "-")
                else:
                    hasil["records"][rtype] = []
                    result(rtype, "(lewati, butuh 'requests')")
        except socket.gaierror:
            hasil["records"][rtype] = []
            result(rtype, "-")
        except Exception as e:
            hasil["records"][rtype] = []
            result(rtype, "Error ({})".format(e))

    if simpan_file:
        simpan_hasil(simpan_file, hasil)



def whois_lookup(domain, simpan_file=None):
    section("WHOIS LOOKUP", icon="whois")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "whois": ""}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(("whois.iana.org", 43))
        sock.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        teks = response.decode("utf-8", errors="ignore")
        whois_server = None
        for line_txt in teks.splitlines():
            if line_txt.lower().startswith("whois:"):
                whois_server = line_txt.split(":", 1)[1].strip()
                break

        if whois_server:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(15)
            sock2.connect((whois_server, 43))
            sock2.sendall((domain + "\r\n").encode())
            resp2 = b""
            while True:
                chunk = sock2.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
            sock2.close()
            teks = resp2.decode("utf-8", errors="ignore")

        hasil["whois"] = teks
        print(teks[:1500])
        if len(teks) > 1500:
            warning("Hasil dipotong (lihat file JSON untuk lengkap)")

    except Exception as e:
        error("WHOIS lookup gagal: {}".format(e))
        if HAS_REQUESTS:
            try:
                r = requests.get("https://api.whois.vu/?q={}".format(domain), timeout=15)
                print(r.text[:1500])
                hasil["whois"] = r.text
            except Exception as e2:
                error("Fallback WHOIS juga gagal: {}".format(e2))

    if simpan_file:
        simpan_hasil(simpan_file, hasil)



def http_headers(url, simpan_file=None):
    section("HTTP HEADER GRABBER", icon="web")
    info("Target: {}".format(url))
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    hasil = {"url": url, "waktu": datetime.now().isoformat(), "headers": {}, "status": None}

    try:
        if HAS_REQUESTS:
            try:
                import urllib3
                urllib3.disable_warnings()
            except ImportError:
                pass
            r = requests.get(url, timeout=15, allow_redirects=True, verify=False)
            hasil["status"] = r.status_code
            hasil["final_url"] = r.url
            for k, v in r.headers.items():
                hasil["headers"][k] = v
                result(k, v)
            result("Status Code", str(r.status_code))
            result("Final URL", r.url)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Toolkit/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                hasil["status"] = resp.status
                hasil["final_url"] = resp.geturl()
                for k, v in resp.headers.items():
                    hasil["headers"][k] = v
                    result(k, v)
                result("Status Code", str(resp.status))
                result("Final URL", resp.geturl())
    except Exception as e:
        error("Gagal mengambil header: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "search", "dev", "test", "staging", "api", "blog", "shop",
    "admin", "forum", "vpn", "m", "mobile", "app", "beta", "demo",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "ns", "mx",
    "gw", "gateway", "vps", "server", "host", "cdn", "img", "images",
    "static", "media", "files", "download", "upload", "git", "svn",
    "jira", "confluence", "wiki", "redmine", "chat", "support", "help",
    "status", "monitor", "stats", "analytics", "tracking", "news",
]


def subdomain_bruteforce(domain, wordlist_file=None, simpan_file=None):
    section("SUBDOMAIN BRUTE-FORCE", icon="sub")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    subdomains = []
    if wordlist_file and os.path.isfile(wordlist_file):
        try:
            with open(wordlist_file, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            info("Memuat {} entri dari wordlist: {}".format(len(subdomains), wordlist_file))
        except Exception as e:
            error("Gagal membaca wordlist: {}".format(e))
            subdomains = DEFAULT_SUBDOMAINS
    else:
        subdomains = DEFAULT_SUBDOMAINS
        info("Menggunakan wordlist default ({} entri)".format(len(subdomains)))

    ditemukan = []
    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "ditemukan": []}

    for sub in subdomains:
        target = "{}.{}".format(sub, domain)
        try:
            ip = socket.gethostbyname(target)
            success("Ditemukan: {} -> {}".format(target, ip))
            ditemukan.append({"subdomain": target, "ip": ip})
        except socket.gaierror:
            pass
        except Exception:
            pass

    info("Total subdomain ditemukan: {}".format(len(ditemukan)))
    hasil["ditemukan"] = ditemukan

    if simpan_file:
        simpan_hasil(simpan_file, hasil)



COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def port_scan(target, simpan_file=None):
    section("PORT SCANNER", icon="port")
    info("Target: {}".format(target))
    if not validasi_ip(target):
        try:
            target = socket.gethostbyname(target)
            info("Domain direkonsi menjadi {}".format(target))
        except socket.gaierror as e:
            error("Tidak dapat merekonsi host: {}".format(e))
            return

    ports = sorted(COMMON_PORTS.keys())
    info("Memindai {} port umum ...".format(len(ports)))
    terbuka = []
    hasil = {"target": target, "waktu": datetime.now().isoformat(), "open_ports": []}

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result_conn = sock.connect_ex((target, port))
            if result_conn == 0:
                service = COMMON_PORTS.get(port, "unknown")
                success("Port {} TERBUKA ({})".format(port, service))
                terbuka.append({"port": port, "service": service, "status": "open"})
            sock.close()
        except Exception:
            pass

    info("Total port terbuka: {}".format(len(terbuka)))
    hasil["open_ports"] = terbuka

    if simpan_file:
        simpan_hasil(simpan_file, hasil)



PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Twitter/X": "https://twitter.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "VK": "https://vk.com/{}",
}


def username_check(username, simpan_file=None):
    section("USERNAME AVAILABILITY", icon="user")
    info("Target: {}".format(username))
    hasil = {"username": username, "waktu": datetime.now().isoformat(), "results": {}}

    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username)
        try:
            if HAS_REQUESTS:
                r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                if r.status_code == 200:
                    status = "Kemungkinan ADA"
                elif r.status_code == 404:
                    status = "Tidak ada"
                else:
                    status = "Status {}".format(r.status_code)
            else:
                req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Toolkit/2.0"})
                try:
                    urllib.request.urlopen(req, timeout=10)
                    status = "Kemungkinan ADA"
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        status = "Tidak ada"
                    else:
                        status = "Status {}".format(e.code)
                except urllib.error.URLError:
                    status = "Tidak terjangkau"
            result(platform, status)
            hasil["results"][platform] = status
        except Exception as e:
            result(platform, "Error: {}".format(e))
            hasil["results"][platform] = "Error: {}".format(e)

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


def jalankan_semua(target, simpan_file):
    section("JALANKAN SEMUA MODUL", icon="rocket")
    info("Target: {}".format(target))
    print("    Urutan: Pasif -> Ringan Aktif -> Aktif/Agresif")

    if validasi_domain(target):
        line(color=C.DIM + C.WHITE)
        section("FASE 1: PASIF", icon="shield")
        print()
        result("[1/4]", "WHOIS Lookup")
        whois_lookup(target, simpan_file)

        line(color=C.DIM + C.WHITE)
        result("[2/4]", "DNS Lookup")
        dns_lookup(target, simpan_file)

        line(color=C.DIM + C.WHITE)
        section("FASE 2: RINGAN AKTIF", icon="bolt")
        print()
        result("[3/4]", "HTTP Header Grabber")
        http_headers("http://{}".format(target), simpan_file)

        line(color=C.DIM + C.WHITE)
        section("FASE 3: AKTIF / AGRESIF", icon="fire")
        print()
        result("[4/4]", "Subdomain Brute-force")
        subdomain_bruteforce(target, None, simpan_file)

    elif validasi_ip(target):
        line(color=C.DIM + C.WHITE)
        section("FASE 1: PASIF", icon="shield")
        print()
        result("[1/2]", "IP Geolocation Lookup")
        ip_geolocation(target, simpan_file)

        line(color=C.DIM + C.WHITE)
        section("FASE 3: AKTIF / AGRESIF", icon="fire")
        print()
        result("[2/2]", "Port Scanner")
        port_scan(target, simpan_file)

    else:
        if target.startswith(("http://", "https://")):
            http_headers(target, simpan_file)
        else:
            username_check(target, simpan_file)



def tampilkan_menu():
    section("MENU UTAMA", icon="menu")
    menu_item("1", "IP Geolocation Lookup", "geo")
    menu_item("2", "DNS Lookup", "dns")
    menu_item("3", "WHOIS Lookup", "whois")
    menu_item("4", "HTTP Header Grabber", "web")
    menu_item("5", "Subdomain Brute-force", "sub")
    menu_item("6", "Port Scanner", "port")
    menu_item("7", "Username Availability", "user")
    menu_item("8", "Jalankan SEMUA modul (otomatis)", "rocket")
    menu_item("9", "Modul Lanjutan (Advanced OSINT)", "gear")
    menu_item("10", "Keluar", "exit")
    print()


def main():
    header("OSINT HUNTER v2.0", "Open Source Intelligence")

    while True:
        tampilkan_menu()
        pilihan = prompt("Pilih menu [1-10]: ")

        if pilihan == "10":
            footer("Terima kasih telah menggunakan OSINT Toolkit", icon="exit")
            break

        if pilihan == "9":
            if HAS_ADVANCED:
                osint_advanced.main()
                continue
            else:
                error("Modul advanced tidak ditemukan (osint_advanced.py).")
                continue

        if pilihan not in ("1", "2", "3", "4", "5", "6", "7", "8"):
            error("Pilihan tidak valid. Coba lagi.")
            continue

        target = prompt("Masukkan target")
        if not target:
            error("Target tidak boleh kosong.")
            continue

        simpan_file = tanya_simpan(target)
        print()

        try:
            if pilihan == "1":
                ip_geolocation(target, simpan_file)
            elif pilihan == "2":
                dns_lookup(target, simpan_file)
            elif pilihan == "3":
                whois_lookup(target, simpan_file)
            elif pilihan == "4":
                http_headers(target, simpan_file)
            elif pilihan == "5":
                wl = prompt("Masukkan path wordlist (kosongkan untuk default): ")
                wl = wl if wl else None
                subdomain_bruteforce(target, wl, simpan_file)
            elif pilihan == "6":
                port_scan(target, simpan_file)
            elif pilihan == "7":
                username_check(target, simpan_file)
            elif pilihan == "8":
                jalankan_semua(target, simpan_file)
        except KeyboardInterrupt:
            warning("\nDihentikan oleh pengguna.")
        except Exception as e:
            error("Terjadi error: {}".format(e))

        input(c("\nTekan ENTER untuk kembali ke menu utama...", C.DIM + C.WHITE))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        footer("Dihentikan oleh pengguna.", icon="exit")
        sys.exit(0)
