"""
IP Tracker & Analysis Tool
Geolocation, Abuse Check, WHOIS, ASN, Traceroute, Interactive Map, PDF Export
"""

import requests
import socket
import subprocess
import json
import sys
import platform
import os
from datetime import datetime

try:
    import folium
    FOLIUM_OK = True
except ImportError:
    FOLIUM_OK = False

try:
    from fpdf import FPDF
    FPDF_OK = True
except ImportError:
    FPDF_OK = False


# ── CONFIG ────────────────────────────────────────────────────────────────────
# Daftar API key AbuseIPDB gratis di: https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"


# ── FOLDER OUTPUT ─────────────────────────────────────────────────────────────

def setup_output_folder():
    """Buat folder output untuk nyimpen semua hasil analisis."""
    print("\n" + "="*55)
    print("  SETUP FOLDER OUTPUT")
    print("="*55)
    print("  Semua hasil (peta, PDF, JSON, TXT) akan disimpan")
    print("  di dalam folder yang kamu buat.\n")

    while True:
        name = input("  Nama folder: ").strip()
        if not name:
            print("  [!] Nama tidak boleh kosong.")
            continue
        safe = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip()
        safe = safe.replace(" ", "_")
        if not safe:
            print("  [!] Nama mengandung karakter tidak valid.")
            continue
        break

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = os.path.join(os.getcwd(), f"{safe}_{ts}")
    os.makedirs(folder, exist_ok=True)
    print(f"\n  Folder dibuat: {folder}\n")
    return folder


def show_folder_contents(folder):
    """Tampilkan daftar file yang sudah dibuat setelah analisis selesai."""
    print(f"\n{'='*55}")
    print(f"  HASIL TERSIMPAN: {os.path.basename(folder)}")
    print(f"{'='*55}")
    files = sorted(os.listdir(folder))
    total = 0
    icons = {".html": "🗺 ", ".pdf": "📄 ", ".json": "📋 ", ".txt": "📝 "}
    for f in files:
        path = os.path.join(folder, f)
        size = os.path.getsize(path)
        total += size
        ext = os.path.splitext(f)[1].lower()
        icon = icons.get(ext, "📁 ")
        print(f"  {icon}{f:45s} {size/1024:6.1f} KB")
    print(f"  {'─'*51}")
    print(f"  {len(files)} file  |  {total/1024:.1f} KB total")
    print(f"  Path: {folder}")


# ── GEOLOCATION ───────────────────────────────────────────────────────────────

def get_geolocation(ip):
    """Cek lokasi IP dari 3 sumber berbeda, bandingkan hasilnya."""
    results = {}

    # Sumber 1: ip-api.com
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        d = r.json()
        if d.get("status") == "success":
            results["ip-api.com"] = {
                "ip": d.get("query"),
                "negara": f"{d.get('country')} ({d.get('countryCode')})",
                "region": d.get("regionName"),
                "kota": d.get("city"),
                "koordinat": f"{d.get('lat')}, {d.get('lon')}",
                "lat": d.get("lat"),
                "lon": d.get("lon"),
                "timezone": d.get("timezone"),
                "isp": d.get("isp"),
                "organisasi": d.get("org"),
                "as": d.get("as"),
                "mobile": d.get("mobile"),
                "proxy": d.get("proxy"),
                "hosting": d.get("hosting"),
            }
    except Exception as e:
        results["ip-api.com"] = {"error": str(e)}

    # Sumber 2: ipinfo.io
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        d = r.json()
        if "bogon" not in d:
            loc = d.get("loc", "0,0").split(",")
            results["ipinfo.io"] = {
                "ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "kota": d.get("city"),
                "region": d.get("region"),
                "negara": d.get("country"),
                "koordinat": d.get("loc"),
                "lat": float(loc[0]) if loc[0] else None,
                "lon": float(loc[1]) if len(loc) > 1 else None,
                "org": d.get("org"),
                "timezone": d.get("timezone"),
            }
    except Exception as e:
        results["ipinfo.io"] = {"error": str(e)}

    # Sumber 3: ipwho.is
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        d = r.json()
        if d.get("success"):
            results["ipwho.is"] = {
                "ip": d.get("ip"),
                "tipe": d.get("type"),
                "negara": f"{d.get('country')} ({d.get('country_code')})",
                "region": d.get("region"),
                "kota": d.get("city"),
                "koordinat": f"{d.get('latitude')}, {d.get('longitude')}",
                "lat": d.get("latitude"),
                "lon": d.get("longitude"),
                "timezone": d.get("timezone", {}).get("id"),
                "isp": d.get("connection", {}).get("isp"),
                "org": d.get("connection", {}).get("org"),
                "asn": d.get("connection", {}).get("asn"),
            }
    except Exception as e:
        results["ipwho.is"] = {"error": str(e)}

    return results


def get_avg_coords(geo_results):
    """Rata-rata koordinat dari semua sumber yang berhasil."""
    lats, lons = [], []
    for data in geo_results.values():
        if isinstance(data, dict) and data.get("lat"):
            try:
                lats.append(float(data["lat"]))
                lons.append(float(data["lon"]))
            except:
                pass
    if lats:
        return round(sum(lats)/len(lats), 6), round(sum(lons)/len(lons), 6)
    return None, None


# ── ABUSE CHECK ───────────────────────────────────────────────────────────────

def check_abuse(ip):
    """Cek reputasi IP lewat AbuseIPDB — butuh API key gratis."""
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        return {
            "status": "API key belum diisi",
            "info": "Daftar gratis di https://www.abuseipdb.com/account/api",
            "cara": "Isi ABUSEIPDB_API_KEY di bagian CONFIG di atas"
        }
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            if score == 0:      level = "AMAN"
            elif score < 25:    level = "RENDAH"
            elif score < 75:    level = "SEDANG"
            else:               level = "TINGGI"
            return {
                "ip": d.get("ipAddress"),
                "skor_abuse": f"{score}/100",
                "level_bahaya": level,
                "total_laporan": d.get("totalReports", 0),
                "pelapor_unik": d.get("numDistinctUsers", 0),
                "laporan_terakhir": d.get("lastReportedAt", "-"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "negara": d.get("countryCode"),
                "tipe_penggunaan": d.get("usageType"),
                "tor": d.get("isTor"),
                "_score": score,
            }
        elif r.status_code == 401:
            return {"error": "API key tidak valid"}
        elif r.status_code == 429:
            return {"error": "Rate limit tercapai (maks 1000/hari untuk akun gratis)"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ── REVERSE DNS ───────────────────────────────────────────────────────────────

def get_reverse_dns(ip):
    """Cari nama domain yang terdaftar untuk IP ini."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return {"hostname": hostname[0], "aliases": hostname[1], "status": "Ditemukan"}
    except socket.herror as e:
        return {"hostname": "-", "status": f"Tidak ada PTR record: {e}"}
    except Exception as e:
        return {"hostname": "-", "status": f"Error: {e}"}


# ── WHOIS / RDAP ──────────────────────────────────────────────────────────────

def get_whois(ip):
    """Cek info registrasi IP lewat RDAP (atau fallback ke whois)."""
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            info = {
                "handle": d.get("handle", "-"),
                "nama_network": d.get("name", "-"),
                "ip_start": d.get("startAddress", "-"),
                "ip_end": d.get("endAddress", "-"),
                "tipe": d.get("type", "-"),
            }
            for ev in d.get("events", []):
                if ev.get("eventAction") == "registration":
                    info["tanggal_registrasi"] = ev.get("eventDate", "-")
                if ev.get("eventAction") == "last changed":
                    info["terakhir_diubah"] = ev.get("eventDate", "-")
            contacts = []
            for entity in d.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [])
                name = "-"
                if isinstance(vcard, list) and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            name = field[3]
                contacts.append({"roles": ", ".join(roles), "nama": name})
            info["kontak"] = contacts
            return {"rdap": info}
        return {"error": f"RDAP HTTP {r.status_code}"}
    except Exception as e:
        try:
            result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
            lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("%")]
            return {"whois_raw": lines[:30]}
        except Exception as e2:
            return {"error": f"{e} | whois: {e2}"}


# ── ASN ───────────────────────────────────────────────────────────────────────

def get_asn(ip):
    """Cari info Autonomous System Number dari IP ini."""
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=8)
        if r.status_code == 200:
            prefixes = r.json().get("data", {}).get("prefixes", [])
            return [{
                "asn": p.get("asn", {}).get("asn"),
                "nama": p.get("asn", {}).get("name"),
                "deskripsi": p.get("asn", {}).get("description"),
                "negara": p.get("asn", {}).get("country_code"),
                "prefix": p.get("prefix"),
                "rir": p.get("rir_name"),
            } for p in prefixes] or [{"info": "Tidak ada data prefix BGP"}]
        return [{"error": f"HTTP {r.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


# ── TRACEROUTE ────────────────────────────────────────────────────────────────

def do_traceroute(ip, max_hops=20):
    """Lacak rute paket dari mesin ini ke IP target."""
    os_name = platform.system().lower()
    if os_name == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-d", ip]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-n", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return [l for l in result.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        return ["[!] Timeout setelah 60 detik"]
    except FileNotFoundError:
        return ["[!] traceroute tidak tersedia. Install: sudo apt install traceroute"]
    except Exception as e:
        return [f"[!] Error: {e}"]


# ── PETA INTERAKTIF ───────────────────────────────────────────────────────────

def generate_map(ip, geo_results, abuse_data, rdns_data, asn_data, output_path):
    """Buat peta HTML interaktif dengan sidebar info IP."""
    if not FOLIUM_OK:
        return False, "folium belum terinstall. Jalankan: pip install folium"

    lat, lon = get_avg_coords(geo_results)
    if lat is None:
        return False, "Koordinat tidak tersedia dari sumber manapun"

    gmaps_url = f"https://www.google.com/maps?q={lat},{lon}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    geo_main = geo_results.get("ip-api.com") or next(
        (v for v in geo_results.values() if isinstance(v, dict) and "error" not in v), {}
    )

    # Abuse info
    has_abuse = "error" not in abuse_data and "status" not in abuse_data
    abuse_score   = abuse_data.get("skor_abuse", "N/A")   if has_abuse else "N/A"
    abuse_level   = abuse_data.get("level_bahaya", "-")   if has_abuse else abuse_data.get("status", abuse_data.get("error", "-"))
    abuse_reports = abuse_data.get("total_laporan", "-")  if has_abuse else "-"

    score_val = 0
    try:
        score_val = int(str(abuse_score).replace("/100", ""))
    except:
        pass
    score_color = "#22c55e" if score_val == 0 else "#eab308" if score_val < 25 else "#f97316" if score_val < 75 else "#ef4444"

    hostname = rdns_data.get("hostname", "-")
    asn_info = asn_data[0] if asn_data else {}
    asn_str  = f"AS{asn_info.get('asn', '-')} {asn_info.get('nama', '')}" if asn_info.get("asn") else "-"
    sources_ok = [k for k, v in geo_results.items() if isinstance(v, dict) and "error" not in v]

    sidebar_html = f"""
    <div id="sidebar" style="
        position:fixed; top:10px; right:10px; z-index:9999;
        background:rgba(15,23,42,0.93); color:#e2e8f0;
        border-radius:12px; padding:18px 20px; width:290px;
        font-family:'Segoe UI',Arial,sans-serif; font-size:13px;
        box-shadow:0 8px 32px rgba(0,0,0,0.5);
        border:1px solid rgba(255,255,255,0.08);
        max-height:92vh; overflow-y:auto;">

      <div style="font-size:15px;font-weight:700;color:#7dd3fc;margin-bottom:12px;">
        🔍 IP Analysis Report
      </div>

      <div style="background:rgba(125,211,252,0.1);border-radius:8px;padding:10px;margin-bottom:12px;border-left:3px solid #7dd3fc;">
        <div style="color:#94a3b8;font-size:11px;margin-bottom:3px;">TARGET IP</div>
        <div style="font-size:16px;font-weight:700;color:#f8fafc;letter-spacing:1px;">{ip}</div>
        <div style="color:#94a3b8;font-size:11px;margin-top:3px;">{timestamp}</div>
      </div>

      <div style="margin-bottom:10px;">
        <div style="color:#94a3b8;font-size:11px;margin-bottom:4px;text-transform:uppercase;">⚠ Abuse Score</div>
        <div style="display:flex;align-items:center;gap:8px;">
          <div style="background:{score_color};color:#fff;font-weight:700;font-size:18px;
              border-radius:8px;padding:4px 12px;min-width:60px;text-align:center;">{abuse_score}</div>
          <div style="color:#cbd5e1;font-size:12px;">{abuse_level}</div>
        </div>
        <div style="color:#94a3b8;font-size:11px;margin-top:4px;">Total laporan: {abuse_reports}</div>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:10px 0;">

      <div style="margin-bottom:10px;">
        <div style="color:#94a3b8;font-size:11px;margin-bottom:6px;text-transform:uppercase;">📍 Lokasi</div>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="color:#94a3b8;padding:2px 0;width:90px;">Negara</td><td style="color:#e2e8f0;">{geo_main.get('negara','-')}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">Region</td><td style="color:#e2e8f0;">{geo_main.get('region','-')}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">Kota</td><td style="color:#e2e8f0;">{geo_main.get('kota','-')}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">Koordinat</td><td style="color:#e2e8f0;">{lat}, {lon}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">Timezone</td><td style="color:#e2e8f0;">{geo_main.get('timezone','-')}</td></tr>
        </table>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:10px 0;">

      <div style="margin-bottom:10px;">
        <div style="color:#94a3b8;font-size:11px;margin-bottom:6px;text-transform:uppercase;">🌐 Jaringan</div>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="color:#94a3b8;padding:2px 0;width:90px;">ISP</td><td style="color:#e2e8f0;word-break:break-word;">{geo_main.get('isp','-')}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">ASN</td><td style="color:#e2e8f0;">{asn_str}</td></tr>
          <tr><td style="color:#94a3b8;padding:2px 0;">Hostname</td><td style="color:#e2e8f0;word-break:break-word;">{hostname}</td></tr>
        </table>
      </div>

      <div style="margin-bottom:10px;">
        <div style="color:#94a3b8;font-size:11px;margin-bottom:6px;text-transform:uppercase;">🚩 Flag</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;">
          <span style="background:{'rgba(249,115,22,0.2)' if geo_main.get('mobile') else 'rgba(255,255,255,0.05)'};color:{'#fb923c' if geo_main.get('mobile') else '#64748b'};border-radius:5px;padding:3px 8px;font-size:11px;">📱 Mobile: {'Ya' if geo_main.get('mobile') else 'Tidak'}</span>
          <span style="background:{'rgba(239,68,68,0.2)' if geo_main.get('proxy') else 'rgba(255,255,255,0.05)'};color:{'#f87171' if geo_main.get('proxy') else '#64748b'};border-radius:5px;padding:3px 8px;font-size:11px;">🔒 Proxy: {'Ya' if geo_main.get('proxy') else 'Tidak'}</span>
          <span style="background:{'rgba(249,115,22,0.2)' if geo_main.get('hosting') else 'rgba(255,255,255,0.05)'};color:{'#fb923c' if geo_main.get('hosting') else '#64748b'};border-radius:5px;padding:3px 8px;font-size:11px;">☁ Hosting: {'Ya' if geo_main.get('hosting') else 'Tidak'}</span>
        </div>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:10px 0;">

      <div style="color:#94a3b8;font-size:11px;margin-bottom:4px;text-transform:uppercase;">
        📡 Sumber Data ({len(sources_ok)}/3)
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;">
        {"".join([f'<span style="background:rgba(34,197,94,0.15);color:#4ade80;border-radius:4px;padding:2px 7px;font-size:10px;">✓ {s}</span>' for s in sources_ok])}
        {"".join([f'<span style="background:rgba(239,68,68,0.15);color:#f87171;border-radius:4px;padding:2px 7px;font-size:10px;">✗ {s}</span>' for s in geo_results if s not in sources_ok])}
      </div>

      <div style="background:rgba(234,179,8,0.1);border-radius:6px;padding:8px;border-left:3px solid #eab308;font-size:11px;color:#fde68a;">
        ⚠ Akurasi geolokasi IP sekitar 5–50 km. Lokasi fisik yang tepat tidak bisa ditentukan hanya dari IP.
      </div>

      <a href="{gmaps_url}" target="_blank" style="
          display:block;margin-top:10px;text-align:center;
          background:rgba(59,130,246,0.2);color:#93c5fd;
          border-radius:7px;padding:8px;text-decoration:none;
          font-size:12px;border:1px solid rgba(59,130,246,0.3);">
        🗺 Buka di Google Maps
      </a>
    </div>
    """

    m = folium.Map(location=[lat, lon], zoom_start=12, tiles="CartoDB dark_matter")
    colors = {"ip-api.com": "red", "ipinfo.io": "blue", "ipwho.is": "orange"}

    for api_name, data in geo_results.items():
        if isinstance(data, dict) and data.get("lat"):
            try:
                alat, alon = float(data["lat"]), float(data["lon"])
                popup_html = (
                    f"<b>{api_name}</b><br>"
                    f"IP: {data.get('ip', ip)}<br>"
                    f"Kota: {data.get('kota', '-')}<br>"
                    f"ISP: {data.get('isp', data.get('org', '-'))}<br>"
                    f"Koordinat: {alat:.4f}, {alon:.4f}"
                )
                folium.Marker(
                    location=[alat, alon],
                    popup=folium.Popup(popup_html, max_width=250),
                    tooltip=api_name,
                    icon=folium.Icon(color=colors.get(api_name, "gray"), icon="info-sign")
                ).add_to(m)
                folium.Circle(
                    location=[alat, alon], radius=5000,
                    color="#f97316", fill=True, fill_opacity=0.08,
                    tooltip="Radius akurasi ~5km"
                ).add_to(m)
            except:
                pass

    m.get_root().html.add_child(folium.Element(sidebar_html))
    m.save(output_path)
    return True, gmaps_url


# ── EXPORT PDF ────────────────────────────────────────────────────────────────

def export_pdf(ip, data_all, output_path):
    """Buat laporan PDF dari semua hasil analisis."""
    if not FPDF_OK:
        return False, "fpdf2 belum terinstall. Jalankan: pip install fpdf2"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(125, 211, 252)
    pdf.set_y(12)
    pdf.cell(0, 10, "IP ANALYSIS REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 8, f"Generated: {data_all.get('timestamp', '-')}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)
    pdf.set_text_color(30, 30, 30)

    def section(title):
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(30, 64, 175)
        pdf.cell(0, 8, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)

    def row(label, value, indent=8):
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_x(indent)
        pdf.cell(55, 6, str(label) + ":", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 6, str(value) if value not in (None, "") else "-")

    section("TARGET IP")
    row("IP Address", ip)
    row("Timestamp", data_all.get("timestamp", "-"))
    pdf.ln(4)

    section("ABUSE REPUTATION (AbuseIPDB)")
    abuse = data_all.get("abuse", {})
    if "error" in abuse:
        row("Status", abuse["error"])
    elif "status" in abuse:
        row("Status", abuse["status"])
        row("Info", abuse.get("info", ""))
    else:
        for k, v in abuse.items():
            if not k.startswith("_"):
                row(k.replace("_", " ").title(), v)
    pdf.ln(4)

    section("GEOLOCATION (Multi-API)")
    for api_name, data in data_all.get("geolocation", {}).items():
        pdf.set_font("Helvetica", "BI", 9)
        pdf.set_x(8)
        pdf.cell(0, 6, f"Sumber: {api_name}", new_x="LMARGIN", new_y="NEXT")
        if isinstance(data, dict):
            for k, v in data.items():
                if k not in ("lat", "lon", "error") and v is not None:
                    row(k.replace("_", " ").title(), v, indent=14)
        pdf.ln(2)
    pdf.ln(2)

    section("REVERSE DNS")
    for k, v in data_all.get("reverse_dns", {}).items():
        row(k.title(), v)
    pdf.ln(4)

    section("WHOIS / RDAP")
    whois = data_all.get("whois", {})
    if "rdap" in whois:
        for k, v in whois["rdap"].items():
            if k != "kontak":
                row(k.replace("_", " ").title(), v)
    elif "error" in whois:
        row("Error", whois["error"])
    pdf.ln(4)

    section("ASN")
    for asn in data_all.get("asn", []):
        for k, v in asn.items():
            row(k.replace("_", " ").title(), v)
    pdf.ln(4)

    section("TRACEROUTE")
    pdf.set_font("Courier", "", 8)
    for line in data_all.get("traceroute", [])[:25]:
        pdf.set_x(8)
        pdf.multi_cell(0, 5, line)
    pdf.ln(4)

    section("OUTPUT FILES")
    row("Peta HTML", data_all.get("maps", {}).get("map_file", "-"))
    row("Google Maps", data_all.get("maps", {}).get("google_maps_url", "-"))
    pdf.ln(4)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 5,
        "Catatan: Laporan ini dibuat untuk keperluan edukasi dan riset teknis. "
        "Akurasi geolokasi IP sekitar 5-50 km. "
        "Sumber data: ip-api.com, ipinfo.io, ipwho.is, AbuseIPDB."
    )
    pdf.output(output_path)
    return True, None


# ── EXPORT JSON + TXT ─────────────────────────────────────────────────────────

def export_text(ip, data_all, folder):
    """Simpan hasil ke file JSON dan TXT."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"report_{ip.replace('.', '_')}_{ts}"

    # JSON
    json_path = os.path.join(folder, f"{base}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data_all, f, indent=2, ensure_ascii=False, default=str)

    # TXT
    txt_path = os.path.join(folder, f"{base}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"IP ANALYSIS REPORT\nTarget: {ip}\nWaktu: {data_all.get('timestamp')}\n\n")

        f.write("[ABUSE REPUTATION]\n")
        for k, v in data_all.get("abuse", {}).items():
            if not k.startswith("_"):
                f.write(f"  {k}: {v}\n")

        f.write("\n[GEOLOCATION]\n")
        for api, d in data_all.get("geolocation", {}).items():
            f.write(f"  [{api}]\n")
            if isinstance(d, dict):
                for k, v in d.items():
                    if k not in ("lat", "lon"):
                        f.write(f"    {k}: {v}\n")

        f.write("\n[REVERSE DNS]\n")
        for k, v in data_all.get("reverse_dns", {}).items():
            f.write(f"  {k}: {v}\n")

        f.write("\n[WHOIS]\n")
        whois = data_all.get("whois", {})
        if "rdap" in whois:
            for k, v in whois["rdap"].items():
                f.write(f"  {k}: {v}\n")

        f.write("\n[ASN]\n")
        for asn in data_all.get("asn", []):
            for k, v in asn.items():
                f.write(f"  {k}: {v}\n")

        f.write("\n[TRACEROUTE]\n")
        for line in data_all.get("traceroute", []):
            f.write(f"  {line}\n")

    return json_path, txt_path


# ── DISPLAY HELPERS ───────────────────────────────────────────────────────────

def print_header(title):
    print(f"\n{'='*55}\n  {title}\n{'='*55}")

def print_dict(d, indent=4):
    pad = " " * indent
    skip = ("lat", "lon", "_score", "_level_color")
    for k, v in d.items():
        if k in skip:
            continue
        if isinstance(v, dict):
            print(f"{pad}{k}:")
            print_dict(v, indent + 4)
        elif isinstance(v, list):
            print(f"{pad}{k}:")
            for item in v:
                if isinstance(item, dict):
                    for ik, iv in item.items():
                        print(f"{pad}    {ik}: {iv}")
                    print()
                else:
                    print(f"{pad}    - {item}")
        else:
            print(f"{pad}{k:28s}: {v}")


# ── MAIN ANALYSIS ─────────────────────────────────────────────────────────────

def analyze(ip, output_folder):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_ip   = ip.replace(".", "_")

    print(f"\n{'#'*55}")
    print(f"  IP TRACKER & ANALYSIS TOOL")
    print(f"  Target : {ip}")
    print(f"  Waktu  : {timestamp}")
    print(f"  Folder : {output_folder}")
    print(f"{'#'*55}")

    data_all = {"ip": ip, "timestamp": timestamp, "output_folder": output_folder}

    # 1. Abuse check
    print_header("1. REPUTASI IP (AbuseIPDB)")
    abuse = check_abuse(ip)
    data_all["abuse"] = abuse
    print_dict(abuse)

    # 2. Geolocation
    print_header("2. GEOLOCATION (Multi-API)")
    geo = get_geolocation(ip)
    data_all["geolocation"] = geo
    for api_name, data in geo.items():
        print(f"\n  [Sumber: {api_name}]")
        if "error" in data:
            print(f"    Error: {data['error']}")
        else:
            print_dict(data)

    lat, lon = get_avg_coords(geo)
    if lat:
        print(f"\n  Google Maps: https://www.google.com/maps?q={lat},{lon}")

    # 3. Reverse DNS
    print_header("3. REVERSE DNS")
    rdns = get_reverse_dns(ip)
    data_all["reverse_dns"] = rdns
    print_dict(rdns)

    # 4. WHOIS
    print_header("4. WHOIS / RDAP")
    whois = get_whois(ip)
    data_all["whois"] = whois
    if "rdap" in whois:
        print_dict(whois["rdap"])
    elif "whois_raw" in whois:
        for line in whois["whois_raw"]:
            print(f"    {line}")
    else:
        print(f"    {whois.get('error')}")

    # 5. ASN
    print_header("5. ASN LOOKUP")
    asns = get_asn(ip)
    data_all["asn"] = asns
    for i, asn in enumerate(asns, 1):
        print(f"\n  [Prefix #{i}]")
        print_dict(asn)

    # 6. Traceroute
    print_header("6. TRACEROUTE")
    print("  Melacak rute paket... (bisa sampai 60 detik)\n")
    hops = do_traceroute(ip)
    data_all["traceroute"] = hops
    for line in hops:
        print(f"  {line}")

    # 7. Peta HTML
    print_header("7. PETA INTERAKTIF")
    map_path = os.path.join(output_folder, f"map_{safe_ip}.html")
    ok, gmaps_or_err = generate_map(ip, geo, abuse, rdns, asns, map_path)
    data_all["maps"] = {
        "map_file": map_path if ok else "-",
        "google_maps_url": gmaps_or_err if ok else "-",
    }
    if ok:
        print(f"  Peta HTML   : {map_path}")
        print(f"  Google Maps : {gmaps_or_err}")
        print("  Buka file HTML di browser untuk lihat peta + sidebar!")
    else:
        print(f"  {gmaps_or_err}")

    # 8. PDF
    print_header("8. EXPORT PDF")
    pdf_path = os.path.join(output_folder, f"report_{safe_ip}.pdf")
    ok_pdf, pdf_err = export_pdf(ip, data_all, pdf_path)
    data_all["pdf"] = pdf_path if ok_pdf else pdf_err
    if ok_pdf:
        print(f"  PDF tersimpan: {pdf_path}")
    else:
        print(f"  {pdf_err}")

    # 9. JSON + TXT
    print_header("9. EXPORT JSON & TXT")
    json_path, txt_path = export_text(ip, data_all, output_folder)
    print(f"  JSON : {json_path}")
    print(f"  TXT  : {txt_path}")

    show_folder_contents(output_folder)
    print(f"\n{'#'*55}\n  ANALISIS SELESAI\n{'#'*55}\n")


def main():
    print("\n" + "="*55)
    print("  IP TRACKER & ANALYSIS TOOL")
    print("  Geolocation | Abuse | WHOIS | ASN | Peta | PDF")
    print("="*55)
    print("\nINFO: Untuk cek reputasi IP, daftarkan API key gratis di:")
    print("  https://www.abuseipdb.com/account/api\n")

    print("  1. Cek IP saya sendiri")
    print("  2. Masukkan IP tertentu")
    print("  3. Keluar")

    pilihan = input("\nPilih (1/2/3): ").strip()

    if pilihan == "1":
        try:
            my_ip = requests.get("https://api.ipify.org?format=json", timeout=5).json()["ip"]
            print(f"\nIP publik kamu: {my_ip}")
        except:
            my_ip = input("Gagal detect otomatis. Masukkan IP kamu: ").strip()
        folder = setup_output_folder()
        analyze(my_ip, folder)

    elif pilihan == "2":
        ip = input("Masukkan IP address: ").strip()
        if not ip:
            print("[!] IP tidak boleh kosong.")
            return
        folder = setup_output_folder()
        analyze(ip, folder)

    elif pilihan == "3":
        print("Sampai jumpa!")
        sys.exit(0)

    else:
        print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()
