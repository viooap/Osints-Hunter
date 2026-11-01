#!/usr/bin/env python3
"""
============================================================
OSINT HUNTER v2.0 - Advanced Module
============================================================
Modul lanjutan tanpa API key, menggunakan sumber publik.
Tampilan modern.

Fitur:
  1. Subdomain via Certificate Transparency (crt.sh)
  2. Wayback Machine URL History
  3. SSL/TLS Certificate Info
  4. HTTP Technology Detection
  5. Port Banner Grabber
  6. Reverse DNS Lookup
  7. MX Record (Email Server)
  8. Image EXIF Metadata
  9. Google Dork Generator
  10. Jalankan semua advanced tools (otomatis)
  0. Kembali ke menu utama

PERINGATAN HUKUM & ETIKA:
  Gunakan HANYA untuk pendidikan, riset keamanan, dan pengujian
  pada aset yang Anda miliki atau memiliki izin tertulis.

Versi : 2.0
============================================================
"""

import json
import socket
import ssl
import os
import sys
from datetime import datetime

from ui import (
    C, BOX, ICON, c, get_hasil_path,
    header, section, menu_item, line,
    success, error, info, warning, result, box,
    prompt, confirm, footer, supports_color
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Utilitas
# ---------------------------------------------------------------------------
def validasi_domain(domain):
    return domain and "." in domain and " " not in domain


def validasi_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
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


# ---------------------------------------------------------------------------
# Fitur 1: Subdomain via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------
def ct_subdomain(domain, simpan_file=None):
    section("CERTIFICATE TRANSPARENCY (crt.sh)", icon="cert")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    if not HAS_REQUESTS:
        error("Butuh library 'requests' untuk fitur ini.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "subdomains": []}
    url = "https://crt.sh/"
    params = {"q": "%.{}".format(domain), "output": "json"}

    try:
        import urllib3
        try:
            urllib3.disable_warnings()
        except Exception:
            pass
        r = requests.get(url, params=params, timeout=25, verify=False)
        if r.status_code != 200 or not r.text.strip():
            error("Tidak ada respons dari crt.sh.")
            return

        data = r.json()
        subs = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line_txt in name_value.split("\n"):
                line_txt = line_txt.strip().lower()
                if line_txt and (line_txt.endswith("." + domain) or line_txt == domain):
                    subs.add(line_txt)

        subs = sorted(subs)
        hasil["subdomains"] = subs
        info("Ditemukan {} subdomain:".format(len(subs)))
        for s in subs[:100]:
            success("- {}".format(s))
        if len(subs) > 100:
            info("... dan {} lagi (lihat file JSON)".format(len(subs) - 100))

    except Exception as e:
        error("Gagal query crt.sh: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 2: Wayback Machine URL History
# ---------------------------------------------------------------------------
def wayback_history(domain, simpan_file=None):
    section("WAYBACK MACHINE URL HISTORY", icon="search")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    if not HAS_REQUESTS:
        error("Butuh library 'requests' untuk fitur ini.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "urls": []}
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": "{}/*".format(domain),
        "output": "json",
        "limit": "100",
        "collapse": "urlkey",
    }

    try:
        r = requests.get(url, params=params, timeout=30, verify=False)
        if r.status_code != 200 or not r.text.strip():
            error("Tidak ada data dari Wayback Machine.")
            return

        data = r.json()
        rows = data[1:] if len(data) > 1 else []
        urls = []
        for row in rows:
            if len(row) >= 3:
                ts = row[0]
                original = row[2]
                urls.append({"timestamp": ts, "url": original})

        hasil["urls"] = urls
        info("Ditemukan {} URL terarsip:".format(len(urls)))
        for item in urls[:50]:
            success("[{}] {}".format(item["timestamp"], item["url"]))
        if len(urls) > 50:
            info("... dan {} lagi (lihat file JSON)".format(len(urls) - 50))

    except Exception as e:
        error("Gagal query Wayback Machine: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 3: SSL/TLS Certificate Info
# ---------------------------------------------------------------------------
def ssl_info(domain, simpan_file=None):
    section("SSL/TLS CERTIFICATE INFO", icon="lock")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "cert": {}}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            error("Tidak dapat mengambil sertifikat SSL.")
            return

        subj = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        hasil["cert"]["subject"] = subj
        hasil["cert"]["issuer"] = issuer
        hasil["cert"]["version"] = cert.get("version")
        hasil["cert"]["serial_number"] = cert.get("serialNumber")
        hasil["cert"]["not_before"] = cert.get("notBefore")
        hasil["cert"]["not_after"] = cert.get("notAfter")
        hasil["cert"]["subject_alt_name"] = cert.get("subjectAltName", ())

        result("Subject (CN)", subj.get("commonName", "-"))
        result("Issuer (CN)", issuer.get("commonName", "-"))
        result("Valid dari", cert.get("notBefore", "-"))
        result("Valid hingga", cert.get("notAfter", "-"))
        sans = cert.get("subjectAltName", ())
        if sans:
            result("SAN", ", ".join(str(s) for s in sans[:10]))

    except Exception as e:
        error("Gagal mengambil info SSL: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 4: HTTP Technology Detection
# ---------------------------------------------------------------------------
def tech_detect(target, simpan_file=None):
    section("HTTP TECHNOLOGY DETECTION", icon="web")
    info("Target: {}".format(target))
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    if not HAS_REQUESTS:
        error("Butuh library 'requests' untuk fitur ini.")
        return

    hasil = {"url": target, "waktu": datetime.now().isoformat(), "tech": {}}

    try:
        import urllib3
        try:
            urllib3.disable_warnings()
        except Exception:
            pass
        r = requests.get(target, timeout=15, allow_redirects=True, verify=False)
        headers = r.headers

        tech = {}
        server = headers.get("Server", "")
        if server:
            tech["Web Server"] = server

        powered = headers.get("X-Powered-By", "")
        if powered:
            tech["X-Powered-By"] = powered

        generator = headers.get("X-Generator", "")
        if generator:
            tech["CMS / Generator"] = generator

        cookie = headers.get("Set-Cookie", "")
        if cookie:
            tech["Set-Cookie"] = cookie[:120]

        via = headers.get("Via", "")
        if via:
            tech["Via"] = via

        xframe = headers.get("X-Frame-Options", "")
        if xframe:
            tech["X-Frame-Options"] = xframe

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            tech["Content-Security-Policy"] = csp[:160]

        hasil["tech"] = tech
        result("Status Code", str(r.status_code))
        result("Final URL", r.url)
        if tech:
            for k, v in tech.items():
                result(k, v)
        else:
            warning("Tidak ada teknologi terdeteksi dari header.")

    except Exception as e:
        error("Gagal deteksi teknologi: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 5: Port Banner Grabber
# ---------------------------------------------------------------------------
COMMON_PORTS_BANNER = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]


def banner_grab(target, simpan_file=None):
    section("PORT BANNER GRABBER", icon="banner")
    info("Target: {}".format(target))
    if not validasi_ip(target):
        try:
            target = socket.gethostbyname(target)
            info("Domain direkonsi menjadi {}".format(target))
        except socket.gaierror as e:
            error("Tidak dapat merekonsi host: {}".format(e))
            return

    hasil = {"target": target, "waktu": datetime.now().isoformat(), "banners": []}

    for port in COMMON_PORTS_BANNER:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result_conn = sock.connect_ex((target, port))
            if result_conn == 0:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(target).encode())
                    data = sock.recv(1024)
                    banner_text = data.decode("utf-8", errors="ignore").strip().replace("\n", " | ")
                except Exception:
                    banner_text = "(port terbuka, tidak ada balasan)"
                success("Port {}: {}".format(port, banner_text[:200]))
                hasil["banners"].append({"port": port, "banner": banner_text})
            sock.close()
        except Exception:
            pass

    info("Selesai grab banner pada {} port.".format(len(COMMON_PORTS_BANNER)))

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 6: Reverse DNS
# ---------------------------------------------------------------------------
def reverse_dns(target, simpan_file=None):
    section("REVERSE DNS LOOKUP", icon="net")
    info("Target: {}".format(target))
    if not validasi_ip(target):
        error("Masukkan IP address (bukan domain).")
        return

    hasil = {"ip": target, "waktu": datetime.now().isoformat(), "hostnames": []}

    try:
        name, aliaslist, addrlist = socket.gethostbyaddr(target)
        result("Hostname utama", name)
        result("Alias", ", ".join(aliaslist) if aliaslist else "-")
        result("Address", ", ".join(addrlist))
        hasil["hostnames"] = {"primary": name, "aliases": aliaslist, "addresses": addrlist}
    except socket.herror as e:
        error("Tidak ada PTR record untuk IP ini: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 7: MX Record (Email Server)
# ---------------------------------------------------------------------------
def mx_lookup(domain, simpan_file=None):
    section("MX RECORD / EMAIL SERVER", icon="dns")
    info("Target: {}".format(domain))
    if not validasi_domain(domain):
        error("Format domain tidak valid.")
        return

    hasil = {"domain": domain, "waktu": datetime.now().isoformat(), "mx": []}

    try:
        if HAS_REQUESTS:
            url = "https://dns.google/resolve"
            params = {"name": domain, "type": "MX"}
            r = requests.get(url, params=params, timeout=15)
            data = r.json()
            answers = data.get("Answer", [])
            for ans in answers:
                preference = ans.get("preference", 0)
                exchange = ans.get("data", "")
                result("Priority {}".format(preference), exchange)
                hasil["mx"].append({"preference": preference, "exchange": exchange})
            if not answers:
                warning("Tidak ada record MX.")
        else:
            error("Butuh library 'requests' untuk MX lookup.")
            return
    except Exception as e:
        error("Gagal MX lookup: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 8: Image EXIF Metadata
# ---------------------------------------------------------------------------
def exif_metadata(filepath, simpan_file=None):
    section("IMAGE EXIF METADATA", icon="user")
    info("File: {}".format(filepath))
    if not os.path.isfile(filepath):
        error("File tidak ditemukan: {}".format(filepath))
        return

    hasil = {"file": filepath, "waktu": datetime.now().isoformat(), "exif": {}}

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(filepath)
        exif_data = img.getexif()
        if not exif_data:
            warning("Tidak ada data EXIF pada gambar ini.")
            return

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            result(str(tag), str(value))
            hasil["exif"][str(tag)] = str(value)

    except ImportError:
        error("Library PIL/Pillow tidak terpasang. Pasang dengan: pip install pillow")
        return
    except Exception as e:
        error("Gagal baca EXIF: {}".format(e))
        return

    if simpan_file:
        simpan_hasil(simpan_file, hasil)


# ---------------------------------------------------------------------------
# Fitur 9: Google Dork Generator
# ---------------------------------------------------------------------------
def generate_dorks(domain):
    return {
        "File PDF/Doc": 'site:{} filetype:pdf OR filetype:doc OR filetype:docx'.format(domain),
        "Login Page": 'site:{} inurl:login OR inurl:signin OR inurl:admin'.format(domain),
        "Exposed Config": 'site:{} inurl:config OR inurl:env OR filetype:yml OR filetype:yaml'.format(domain),
        "Index Directory": 'site:{} intitle:"index of"'.format(domain),
        "Subdomain via DNS": 'site:{}'.format(domain),
        "Cached / Backup": 'site:{} filetype:bak OR filetype:old OR filetype:zip'.format(domain),
    }


def google_dork_generator():
    section("GOOGLE DORK GENERATOR", icon="search")
    domain = prompt("Masukkan domain target")
    if not domain:
        error("Domain tidak boleh kosong.")
        return

    dorks = generate_dorks(domain)

    info("Dork yang dihasilkan untuk {}:".format(domain))
    print()
    for nama, dork in dorks.items():
        result(nama, dork)

    simpan = prompt("Simpan daftar dork ke file teks? (y/n): ")
    if simpan == "y":
        nama_file = "google_dorks_{}.txt".format(domain)
        path = get_hasil_path(nama_file)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Google Dorks untuk {}\n\n".format(domain))
                for nama, dork in dorks.items():
                    f.write("{}: {}\n".format(nama, dork))
            success("Disimpan ke: {}".format(path))
        except Exception as e:
            error("Gagal simpan: {}".format(e))


# ---------------------------------------------------------------------------
# Fitur 10: Jalankan semua advanced tools (otomatis)
# ---------------------------------------------------------------------------
def jalankan_semua_advanced(target, simpan_file=None):
    section("JALANKAN SEMUA ADVANCED TOOLS", icon="rocket")
    info("Target: {}".format(target))
    print("    Urutan: Pasif -> Ringan Aktif -> Aktif/Agresif")

    is_domain = validasi_domain(target)
    is_ip = validasi_ip(target)

    ip_target = target
    if is_domain:
        try:
            ip_target = socket.gethostbyname(target)
            info("Domain direkonsi menjadi {}".format(ip_target))
        except socket.gaierror:
            ip_target = None
            warning("Tidak dapat merekonsi domain ke IP (Reverse DNS & Banner Grab dilewati)")

    line(color=C.DIM + C.WHITE)
    section("FASE 1: PASIF (tidak menyentuh server target langsung)", icon="shield")
    print()

    result("[1/8]", "Certificate Transparency Subdomain (crt.sh)")
    if is_domain:
        ct_subdomain(target, simpan_file)
    else:
        warning("Dilewati (butuh domain)")

    line(color=C.DIM + C.WHITE)
    result("[2/8]", "Wayback Machine URL History")
    if is_domain:
        wayback_history(target, simpan_file)
    else:
        warning("Dilewati (butuh domain)")

    line(color=C.DIM + C.WHITE)
    result("[3/8]", "Google Dork Generator")
    if is_domain:
        dorks = generate_dorks(target)
        for nama, dork in dorks.items():
            result(nama, dork)
        dork_file = "google_dorks_{}.txt".format(target)
        path = get_hasil_path(dork_file)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Google Dorks untuk {}\n\n".format(target))
                for nama, dork in dorks.items():
                    f.write("{}: {}\n".format(nama, dork))
            success("Dork disimpan ke: {}".format(path))
        except Exception as e:
            error("Gagal simpan dork: {}".format(e))
    else:
        warning("Dilewati (butuh domain)")

    line(color=C.DIM + C.WHITE)
    section("FASE 2: RINGAN AKTIF (kontak langsung tapi footprint kecil)", icon="bolt")
    print()

    result("[4/8]", "Reverse DNS Lookup")
    if ip_target:
        reverse_dns(ip_target, simpan_file)
    else:
        warning("Dilewati (butuh IP)")

    line(color=C.DIM + C.WHITE)
    result("[5/8]", "MX Record / Email Server")
    if is_domain:
        mx_lookup(target, simpan_file)
    else:
        warning("Dilewati (butuh domain)")

    line(color=C.DIM + C.WHITE)
    result("[6/8]", "HTTP Technology Detection")
    tech_detect(target, simpan_file)

    line(color=C.DIM + C.WHITE)
    result("[7/8]", "SSL/TLS Certificate Info")
    if is_domain:
        ssl_info(target, simpan_file)
    else:
        warning("Dilewati (butuh domain)")

    line(color=C.DIM + C.WHITE)
    section("FASE 3: AKTIF / AGRESIF (bisa terdeteksi oleh target)", icon="fire")
    print()

    result("[8/8]", "Port Banner Grabber")
    if ip_target:
        banner_grab(ip_target, simpan_file)
    else:
        warning("Dilewati (tidak ada IP target)")

    warning("EXIF Metadata dilewati (butuh path file gambar secara manual).")

    footer("Selesai menjalankan semua modul advanced.", icon="sparkle")


# ---------------------------------------------------------------------------
# Menu Advanced
# ---------------------------------------------------------------------------
def tampilkan_menu():
    section("MENU ADVANCED", icon="gear")
    menu_item("1", "Subdomain via Certificate Transparency (crt.sh)", "cert")
    menu_item("2", "Wayback Machine URL History", "search")
    menu_item("3", "SSL/TLS Certificate Info", "lock")
    menu_item("4", "HTTP Technology Detection", "web")
    menu_item("5", "Port Banner Grabber", "banner")
    menu_item("6", "Reverse DNS Lookup", "net")
    menu_item("7", "MX Record (Email Server)", "dns")
    menu_item("8", "Image EXIF Metadata", "user")
    menu_item("9", "Google Dork Generator", "search")
    menu_item("10", "Jalankan semua advanced tools (otomatis)", "rocket")
    menu_item("0", "Kembali ke menu utama", "back")
    print()


def main():
    header("OSINT HUNTER v2.0", "Advanced Module")

    while True:
        tampilkan_menu()
        pilihan = prompt("Pilih menu [0-10]: ")

        if pilihan == "0":
            footer("Kembali ke menu utama.", icon="back")
            break

        if pilihan not in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10"):
            error("Pilihan tidak valid.")
            continue

        target = prompt("Masukkan target")
        if not target:
            error("Target tidak boleh kosong.")
            continue

        simpan_file = None
        jawab = prompt("Simpan hasil ke file JSON? (y/n): ")
        if jawab == "y":
            aman = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in target)
            simpan_file = "adv_{}.json".format(aman)

        try:
            if pilihan == "1":
                ct_subdomain(target, simpan_file)
            elif pilihan == "2":
                wayback_history(target, simpan_file)
            elif pilihan == "3":
                ssl_info(target, simpan_file)
            elif pilihan == "4":
                tech_detect(target, simpan_file)
            elif pilihan == "5":
                banner_grab(target, simpan_file)
            elif pilihan == "6":
                reverse_dns(target, simpan_file)
            elif pilihan == "7":
                mx_lookup(target, simpan_file)
            elif pilihan == "8":
                fp = prompt("Masukkan path file gambar: ")
                exif_metadata(fp, simpan_file)
            elif pilihan == "9":
                google_dork_generator()
            elif pilihan == "10":
                jalankan_semua_advanced(target, simpan_file)
        except KeyboardInterrupt:
            warning("\nDihentikan oleh pengguna.")
        except Exception as e:
            error("Error: {}".format(e))

        input(c("\nTekan ENTER untuk kembali ke menu advanced...", C.DIM + C.WHITE))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        footer("Dihentikan oleh pengguna.", icon="exit")
        sys.exit(0)
