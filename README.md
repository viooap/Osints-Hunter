
# OSINT HUNTER v2.0

Modern **Open Source Intelligence (OSINT)** toolkit written in Python with a cyberpunk neon CLI interface. Designed for security researchers, bug bounty hunters, and students to perform reconnaissance on targets using only public sources.

## ✨ Features

- **IP Geolocation** – country, city, ISP, organization, coordinates
- **DNS Lookup** – A, AAAA, CNAME, MX, NS, TXT records
- **WHOIS Lookup** – domain ownership and registration info
- **HTTP Header Grabber** – server headers and technology detection
- **Subdomain Brute-force** – wordlist-based subdomain discovery
- **Port Scanner** – common port scanning
- **Username Availability** – check across GitHub, Twitter, Instagram, Reddit, etc.
- **Certificate Transparency (crt.sh)** – passive subdomain discovery
- **Wayback Machine** – archived URL history
- **SSL/TLS Certificate Info** – issuer, validity, SAN
- **Port Banner Grabber** – service version detection
- **Reverse DNS** – PTR record lookup
- **MX Record** – email server lookup
- **Image EXIF Metadata** – GPS, camera, software info
- **Google Dork Generator** – ready-to-use search queries

## ⚡ Run Modes

- **Interactive Menu** – choose modules manually
- **Auto Run** – executes all relevant modules in OSINT order (Passive → Light Active → Aggressive)

## 💾 Output

All results are automatically saved to the `hasil/` folder as JSON or TXT files.

## ⚠️ Legal Warning

Use this tool **only** for:
- Educational purposes
- Security research
- Testing assets you own or have written permission to test

Unauthorized use against third parties is illegal. The author is not responsible for misuse.

## 🚀 Installation

```bash
git clone https://github.com/username/Osint-Hunter.git
cd Osint-Hunter
pip install -r requirements.txt
python3 osint_tool.py
```
🛡️ Disclaimer
================================================================================
DISCLAIMER - OSINT HUNTER v2.0
Dibuat oleh: ViZuann
Versi: 2.0
================================================================================

1. TUJUAN PENGGUNAAN
Toolkit OSINT HUNTER v2.0 dibangun khusus untuk:
- Tujuan pendidikan dan pembelajaran keamanan siber
- Riset keamanan siber (cybersecurity research)
- Pengujian keamanan pada aset digital yang Anda miliki sendiri
- Pengujian pada aset yang telah Anda peroleh izin tertulis dari pemiliknya

2. DILARANG KERAS
Penggunaan tool ini untuk hal-hal berikut dilarang secara keras:
- Menyadap, memantau, atau mengumpulkan data orang tanpa izin
- Serang, merusak, atau mengganggu sistem milik pihak lain
- Melakukan pencarian informasi (reconnaissance) pada target tanpa izin
- Menggunakan hasil scan untuk melakukan kegiatan ilegal
- Melanggar undang-undang siber di negara Anda

3. TANGGUNG JAWAB PENGGUNA
Anda sepenuhnya bertanggung jawab atas:
- Memastikan memiliki izin hukum sebelum menguji target
- Mematuhi semua undang-undang perdata dan pidana yang berlaku
- Konsekuensi hukum yang timbul dari penyalahgunaan tool ini
- Keamanan dan kerahasiaan data yang Anda kumpulkan

Pengembang (ViZuann) TIDAK bertanggung jawab atas kerusakan, kerugian, atau
konsekuensi hukum yang terjadi akibat penggunaan tool ini.

4. TIDAK ADA JAMINAN (NO WARRANTY)
Toolkit OSINT HUNTER v2.0 disediakan "sebagaimana adanya" (as-is) tanpa
jaminan apapun, baik tersurat maupun tersirat, termasuk namun tidak terbatas
pada jaminan kelayakan untuk tujuan tertentu, keakuratan hasil scan atau
pencarian, dan ketersediaan layanan pihak ketiga.

Pengembang tidak menjamin bahwa tool ini bebas dari error, bug, atau
kerentanan.

5. LAYANAN Pihak Ketiga
Beberapa fitur dalam tool ini mengandalkan layanan publik gratis, seperti:
- crt.sh (Certificate Transparency)
- web.archive.org (Wayback Machine)
- dns.google (DNS-over-HTTP)
- ip-api.com (IP Geolocation)
- whois.iana.org dan server whois TLD

Ketergantungan pada layanan pihak ketiga berarti ketersediaan dan rate limit
di luar kendali pengembang.

6. HAK CIPTA
OSINT HUNTER v2.0 © 2026 ViZuann. Hak cipta dilindungi undang-undang.

7. KONTAK
Jika Anda memiliki pertanyaan tentang penggunaan yang benar, silakan hubungi
pengembang melalui repositori GitHub resmi.


>Dengan menggunakan OSINT HUNTER v2.0, Anda setuju dengan semua ketentuan di atas.

