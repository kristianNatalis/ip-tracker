# 🔍 IP Tracker & Analysis Tool

Tool untuk menganalisis informasi lengkap sebuah IP address — geolokasi, reputasi, WHOIS, ASN, traceroute, peta interaktif, dan laporan PDF/JSON/TXT.

Tersedia dalam dua mode: **CLI (terminal)** dan **GUI (antarmuka grafis)**.

---

## Fitur

- **Geolokasi** — data dari 3 sumber sekaligus (ip-api.com, ipinfo.io, ipwho.is)
- **Abuse Check** — skor reputasi IP via AbuseIPDB
- **Reverse DNS** — cek hostname dari PTR record
- **WHOIS / RDAP** — info registrasi IP block
- **ASN Lookup** — info Autonomous System via BGPView
- **Traceroute** — lacak rute paket dari mesin kamu ke IP target
- **Peta Interaktif** — file HTML dengan sidebar info, bisa dibuka di browser
- **Export** — laporan dalam format PDF, JSON, dan TXT

---

## Instalasi

### 1. Clone repo

```bash
git clone https://github.com/username/ip-tracker.git
cd ip-tracker
```

### 2. Install dependensi

```bash
pip install -r requirements.txt
```

> **Catatan**: Untuk peta interaktif, butuh `folium`. Untuk export PDF, butuh `fpdf2`. Keduanya sudah ada di `requirements.txt`.

### 3. (Opsional) Daftarkan API key AbuseIPDB

Kalau mau cek reputasi IP, daftar gratis di [abuseipdb.com](https://www.abuseipdb.com/account/api), lalu isi di `src/tracker.py`:

```python
ABUSEIPDB_API_KEY = "isi_api_key_kamu_di_sini"
```

---

## Cara Pakai

### Mode CLI (terminal)

```bash
python src/tracker.py
```

Ikuti pilihan di layar: cek IP kamu sendiri atau masukkan IP tertentu.

### Mode GUI

```bash
python src/gui.py
```

Akan muncul tampilan grafis. Masukkan IP, pilih folder output, klik **Mulai Analisis**.

---

## Struktur Folder

```
ip-tracker/
├── src/
│   ├── tracker.py      # Logika utama (CLI)
│   └── gui.py          # Tampilan grafis (GUI)
├── outputs/            # Folder default hasil analisis (dibuat otomatis)
├── requirements.txt
├── .gitignore
└── README.md
```

Setiap kali analisis, semua hasil disimpan dalam subfolder baru:

```
outputs/
└── ip_8_8_8_8_20250629_143012/
    ├── map_8_8_8_8.html
    ├── report_8_8_8_8.pdf
    ├── report_8_8_8_8_20250629_143012.json
    └── report_8_8_8_8_20250629_143012.txt
```

---

## Dependensi

| Package    | Kegunaan                       |
|------------|-------------------------------|
| `requests` | HTTP request ke API eksternal  |
| `folium`   | Buat peta HTML interaktif      |
| `fpdf2`    | Export laporan ke PDF          |

Semua sudah ada di `requirements.txt`. Tkinter (untuk GUI) sudah bawaan Python.

---

## Catatan

- Akurasi geolokasi IP sekitar **5–50 km** (level kota/ISP). Lokasi fisik yang tepat tidak bisa ditentukan hanya dari IP publik.
- Tool ini dibuat untuk keperluan **edukasi dan riset jaringan**.
- Pakai dengan bertanggung jawab sesuai hukum yang berlaku.

---

## Lisensi

MIT License — bebas dipakai, dimodifikasi, dan didistribusikan.
