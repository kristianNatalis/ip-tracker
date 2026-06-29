"""
IP Tracker GUI
Interface grafis untuk IP Tracker & Analysis Tool
Jalankan: python gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import sys
import os
import requests
from datetime import datetime

# Import fungsi dari tracker.py
sys.path.insert(0, os.path.dirname(__file__))
from tracker import (
    check_abuse, get_geolocation, get_reverse_dns,
    get_whois, get_asn, do_traceroute, generate_map,
    export_pdf, export_text, get_avg_coords
)

# ── WARNA & STYLE ─────────────────────────────────────────────────────────────
BG       = "#0f172a"
PANEL    = "#1e293b"
BORDER   = "#334155"
ACCENT   = "#7dd3fc"
TEXT     = "#e2e8f0"
MUTED    = "#94a3b8"
SUCCESS  = "#4ade80"
WARNING  = "#facc15"
DANGER   = "#f87171"
FONT     = ("Segoe UI", 10)
FONT_SM  = ("Segoe UI", 9)
FONT_LG  = ("Segoe UI", 12, "bold")
MONO     = ("Consolas", 9)


class IPTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Tracker & Analysis Tool")
        self.root.geometry("950x700")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG)

        self.output_folder = None
        self.is_running = False

        self._build_ui()

    # ── UI BUILDER ────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=PANEL, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="🔍  IP Tracker & Analysis Tool",
                 font=("Segoe UI", 16, "bold"), fg=ACCENT, bg=PANEL).pack()
        tk.Label(header, text="Geolocation · Abuse Check · WHOIS · ASN · Traceroute · Peta · PDF",
                 font=FONT_SM, fg=MUTED, bg=PANEL).pack()

        # Input area
        input_frame = tk.Frame(self.root, bg=BG, padx=16, pady=12)
        input_frame.pack(fill="x")

        # IP input row
        ip_row = tk.Frame(input_frame, bg=BG)
        ip_row.pack(fill="x", pady=(0, 8))

        tk.Label(ip_row, text="IP Address:", font=FONT, fg=TEXT, bg=BG, width=12, anchor="w").pack(side="left")

        self.ip_var = tk.StringVar()
        ip_entry = tk.Entry(ip_row, textvariable=self.ip_var, font=FONT,
                            bg=PANEL, fg=TEXT, insertbackground=TEXT,
                            relief="flat", bd=0, highlightthickness=1,
                            highlightbackground=BORDER, highlightcolor=ACCENT)
        ip_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        ip_entry.bind("<Return>", lambda e: self.start_analysis())

        self.btn_my_ip = tk.Button(ip_row, text="IP Saya",
                                   command=self.fill_my_ip, font=FONT_SM,
                                   bg=PANEL, fg=ACCENT, activebackground=BORDER,
                                   activeforeground=ACCENT, relief="flat",
                                   cursor="hand2", padx=10, pady=4)
        self.btn_my_ip.pack(side="left", padx=(0, 6))

        # Folder row
        folder_row = tk.Frame(input_frame, bg=BG)
        folder_row.pack(fill="x", pady=(0, 8))

        tk.Label(folder_row, text="Output folder:", font=FONT, fg=TEXT, bg=BG, width=12, anchor="w").pack(side="left")

        self.folder_var = tk.StringVar(value=os.path.join(os.getcwd(), "outputs"))
        folder_entry = tk.Entry(folder_row, textvariable=self.folder_var, font=FONT,
                                bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                relief="flat", bd=0, highlightthickness=1,
                                highlightbackground=BORDER, highlightcolor=ACCENT)
        folder_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        btn_browse = tk.Button(folder_row, text="Browse",
                               command=self.browse_folder, font=FONT_SM,
                               bg=PANEL, fg=MUTED, activebackground=BORDER,
                               activeforeground=TEXT, relief="flat",
                               cursor="hand2", padx=10, pady=4)
        btn_browse.pack(side="left")

        # Tombol analisis
        btn_row = tk.Frame(input_frame, bg=BG)
        btn_row.pack(fill="x")

        self.btn_analyze = tk.Button(btn_row, text="▶  Mulai Analisis",
                                     command=self.start_analysis,
                                     font=("Segoe UI", 11, "bold"),
                                     bg=ACCENT, fg=BG,
                                     activebackground="#38bdf8", activeforeground=BG,
                                     relief="flat", cursor="hand2",
                                     padx=20, pady=8)
        self.btn_analyze.pack(side="left", padx=(0, 8))

        self.btn_clear = tk.Button(btn_row, text="✕  Clear",
                                   command=self.clear_output,
                                   font=FONT_SM,
                                   bg=PANEL, fg=MUTED,
                                   activebackground=BORDER, activeforeground=TEXT,
                                   relief="flat", cursor="hand2",
                                   padx=14, pady=8)
        self.btn_clear.pack(side="left")

        # Status bar
        self.status_var = tk.StringVar(value="Siap.")
        status_bar = tk.Frame(self.root, bg=PANEL, pady=4)
        status_bar.pack(fill="x")
        self.status_label = tk.Label(status_bar, textvariable=self.status_var,
                                     font=FONT_SM, fg=MUTED, bg=PANEL, anchor="w", padx=12)
        self.status_label.pack(side="left")

        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=150)
        self.progress.pack(side="right", padx=12, pady=2)

        # Tabs: Output + Summary
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.TNotebook", background=BG, borderwidth=0)
        style.configure("Custom.TNotebook.Tab", background=PANEL, foreground=MUTED,
                         padding=[12, 6], font=FONT_SM)
        style.map("Custom.TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", ACCENT)])

        self.notebook = ttk.Notebook(self.root, style="Custom.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Tab 1: Log output
        tab_log = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab_log, text="📋  Log Output")

        self.output_text = scrolledtext.ScrolledText(
            tab_log, font=MONO, bg=PANEL, fg=TEXT,
            insertbackground=TEXT, selectbackground=BORDER,
            relief="flat", wrap="none", padx=10, pady=10
        )
        self.output_text.pack(fill="both", expand=True)
        self.output_text.configure(state="disabled")

        # Tag warna
        self.output_text.tag_config("header", foreground=ACCENT, font=("Consolas", 9, "bold"))
        self.output_text.tag_config("ok",     foreground=SUCCESS)
        self.output_text.tag_config("warn",   foreground=WARNING)
        self.output_text.tag_config("err",    foreground=DANGER)
        self.output_text.tag_config("muted",  foreground=MUTED)
        self.output_text.tag_config("bold",   font=("Consolas", 9, "bold"))

        # Tab 2: Summary card
        tab_summary = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab_summary, text="📊  Ringkasan")

        # Summary canvas dengan scrollbar
        canvas = tk.Canvas(tab_summary, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab_summary, orient="vertical", command=canvas.yview)
        self.summary_frame = tk.Frame(canvas, bg=BG)

        self.summary_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.summary_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._show_empty_summary()

    def _show_empty_summary(self):
        for w in self.summary_frame.winfo_children():
            w.destroy()
        tk.Label(self.summary_frame,
                 text="Belum ada hasil analisis.\nMasukkan IP dan klik 'Mulai Analisis'.",
                 font=FONT, fg=MUTED, bg=BG, justify="center").pack(pady=60)

    # ── ACTIONS ───────────────────────────────────────────────────────────────

    def fill_my_ip(self):
        self.set_status("Mendeteksi IP publik kamu...")
        def _fetch():
            try:
                ip = requests.get("https://api.ipify.org?format=json", timeout=5).json()["ip"]
                self.root.after(0, lambda: self.ip_var.set(ip))
                self.root.after(0, lambda: self.set_status(f"IP kamu: {ip}"))
            except:
                self.root.after(0, lambda: self.set_status("Gagal mendeteksi IP. Cek koneksi internet."))
        threading.Thread(target=_fetch, daemon=True).start()

    def browse_folder(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory(title="Pilih folder output")
        if folder:
            self.folder_var.set(folder)

    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")
        self._show_empty_summary()
        self.set_status("Output dibersihkan.")

    def start_analysis(self):
        if self.is_running:
            messagebox.showwarning("Sedang berjalan", "Analisis sedang berjalan, tunggu sebentar.")
            return

        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("Error", "Masukkan IP address terlebih dahulu.")
            return

        folder_base = self.folder_var.get().strip()
        if not folder_base:
            messagebox.showerror("Error", "Tentukan folder output terlebih dahulu.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_folder = os.path.join(folder_base, f"ip_{ip.replace('.','_')}_{ts}")
        os.makedirs(self.output_folder, exist_ok=True)

        self.notebook.select(0)  # Switch ke tab log
        self.is_running = True
        self.btn_analyze.configure(state="disabled", text="⏳  Menganalisis...")
        self.progress.start(12)
        self._show_empty_summary()

        threading.Thread(target=self._run_analysis, args=(ip,), daemon=True).start()

    def _run_analysis(self, ip):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data_all  = {"ip": ip, "timestamp": timestamp, "output_folder": self.output_folder}
            safe_ip   = ip.replace(".", "_")

            self.log(f"{'='*55}", "header")
            self.log(f"  IP TRACKER & ANALYSIS TOOL", "header")
            self.log(f"  Target : {ip}", "bold")
            self.log(f"  Waktu  : {timestamp}", "muted")
            self.log(f"{'='*55}\n", "header")

            # 1. Abuse
            self.set_status("Mengecek reputasi IP...")
            self.log_section("1. REPUTASI IP (AbuseIPDB)")
            abuse = check_abuse(ip)
            data_all["abuse"] = abuse
            self.log_dict(abuse)

            # 2. Geolocation
            self.set_status("Mengambil data geolokasi...")
            self.log_section("2. GEOLOCATION (3 Sumber)")
            geo = get_geolocation(ip)
            data_all["geolocation"] = geo
            for api_name, data in geo.items():
                self.log(f"\n  [Sumber: {api_name}]", "bold")
                if "error" in data:
                    self.log(f"    Error: {data['error']}", "err")
                else:
                    self.log_dict(data)

            lat, lon = get_avg_coords(geo)
            if lat:
                self.log(f"\n  Google Maps: https://www.google.com/maps?q={lat},{lon}", "ok")

            # 3. Reverse DNS
            self.set_status("Mencari reverse DNS...")
            self.log_section("3. REVERSE DNS")
            rdns = get_reverse_dns(ip)
            data_all["reverse_dns"] = rdns
            self.log_dict(rdns)

            # 4. WHOIS
            self.set_status("Mengambil data WHOIS...")
            self.log_section("4. WHOIS / RDAP")
            whois = get_whois(ip)
            data_all["whois"] = whois
            if "rdap" in whois:
                self.log_dict(whois["rdap"])
            elif "whois_raw" in whois:
                for line in whois["whois_raw"]:
                    self.log(f"    {line}")
            else:
                self.log(f"    {whois.get('error')}", "err")

            # 5. ASN
            self.set_status("Mengambil info ASN...")
            self.log_section("5. ASN LOOKUP")
            asns = get_asn(ip)
            data_all["asn"] = asns
            for i, asn in enumerate(asns, 1):
                self.log(f"\n  [Prefix #{i}]", "bold")
                self.log_dict(asn)

            # 6. Traceroute
            self.set_status("Melacak rute paket (bisa 30–60 detik)...")
            self.log_section("6. TRACEROUTE")
            hops = do_traceroute(ip)
            data_all["traceroute"] = hops
            for line in hops:
                self.log(f"  {line}")

            # 7. Peta HTML
            self.set_status("Membuat peta interaktif...")
            self.log_section("7. PETA INTERAKTIF")
            map_path = os.path.join(self.output_folder, f"map_{safe_ip}.html")
            ok, gmaps_or_err = generate_map(ip, geo, abuse, rdns, asns, map_path)
            data_all["maps"] = {
                "map_file": map_path if ok else "-",
                "google_maps_url": gmaps_or_err if ok else "-",
            }
            if ok:
                self.log(f"  Peta HTML   : {map_path}", "ok")
                self.log(f"  Google Maps : {gmaps_or_err}", "ok")
            else:
                self.log(f"  {gmaps_or_err}", "warn")

            # 8. PDF
            self.set_status("Membuat laporan PDF...")
            self.log_section("8. EXPORT PDF")
            pdf_path = os.path.join(self.output_folder, f"report_{safe_ip}.pdf")
            ok_pdf, pdf_err = export_pdf(ip, data_all, pdf_path)
            data_all["pdf"] = pdf_path if ok_pdf else pdf_err
            if ok_pdf:
                self.log(f"  PDF tersimpan: {pdf_path}", "ok")
            else:
                self.log(f"  {pdf_err}", "warn")

            # 9. JSON + TXT
            self.set_status("Menyimpan JSON & TXT...")
            self.log_section("9. EXPORT JSON & TXT")
            json_path, txt_path = export_text(ip, data_all, self.output_folder)
            self.log(f"  JSON : {json_path}", "ok")
            self.log(f"  TXT  : {txt_path}", "ok")

            # Done
            self.log(f"\n{'#'*55}", "header")
            self.log(f"  ANALISIS SELESAI ✓", "ok")
            self.log(f"  Folder: {self.output_folder}", "muted")
            self.log(f"{'#'*55}\n", "header")

            self.root.after(0, lambda: self._build_summary(ip, data_all, lat, lon))
            self.root.after(0, lambda: self.set_status(f"Selesai — hasil disimpan di {self.output_folder}"))

        except Exception as e:
            self.log(f"\n[ERROR] {e}", "err")
            self.root.after(0, lambda: self.set_status(f"Error: {e}"))
        finally:
            self.root.after(0, self._done)

    def _done(self):
        self.is_running = False
        self.progress.stop()
        self.btn_analyze.configure(state="normal", text="▶  Mulai Analisis")

    # ── SUMMARY CARDS ─────────────────────────────────────────────────────────

    def _build_summary(self, ip, data_all, lat, lon):
        for w in self.summary_frame.winfo_children():
            w.destroy()

        abuse = data_all.get("abuse", {})
        geo   = data_all.get("geolocation", {})
        rdns  = data_all.get("reverse_dns", {})
        asns  = data_all.get("asn", [{}])

        geo_main = geo.get("ip-api.com") or next(
            (v for v in geo.values() if isinstance(v, dict) and "error" not in v), {}
        )

        has_abuse = "error" not in abuse and "status" not in abuse
        score_str = abuse.get("skor_abuse", "N/A") if has_abuse else "N/A"
        level_str = abuse.get("level_bahaya", "-") if has_abuse else "-"
        score_val = 0
        try:
            score_val = int(str(score_str).replace("/100", ""))
        except:
            pass
        score_color = SUCCESS if score_val == 0 else WARNING if score_val < 25 else "#f97316" if score_val < 75 else DANGER

        def card(parent, title, pady=(8, 0)):
            frame = tk.LabelFrame(parent, text=f"  {title}  ",
                                  font=FONT_SM, fg=ACCENT, bg=PANEL,
                                  labelanchor="nw", bd=1, relief="flat",
                                  highlightthickness=1, highlightbackground=BORDER)
            frame.pack(fill="x", padx=12, pady=pady)
            return frame

        def row(parent, label, value, value_color=TEXT):
            f = tk.Frame(parent, bg=PANEL, pady=2)
            f.pack(fill="x", padx=10)
            tk.Label(f, text=label, font=FONT_SM, fg=MUTED, bg=PANEL, width=20, anchor="w").pack(side="left")
            tk.Label(f, text=str(value) if value else "-", font=FONT_SM, fg=value_color, bg=PANEL, anchor="w", wraplength=480).pack(side="left")

        # IP + Score header
        c = card(self.summary_frame, "Target & Abuse Score", pady=(12, 0))
        row(c, "IP Address", ip, ACCENT)
        row(c, "Timestamp", data_all.get("timestamp"))
        row(c, "Abuse Score", score_str, score_color)
        row(c, "Level Bahaya", level_str, score_color)
        row(c, "Total Laporan", abuse.get("total_laporan", "-"))
        row(c, "Tor", "Ya" if abuse.get("tor") else "Tidak")

        # Geolocation
        c = card(self.summary_frame, "📍 Lokasi (ip-api.com)")
        row(c, "Negara",   geo_main.get("negara", "-"))
        row(c, "Region",   geo_main.get("region", "-"))
        row(c, "Kota",     geo_main.get("kota", "-"))
        row(c, "Koordinat", f"{lat}, {lon}" if lat else "-")
        row(c, "Timezone", geo_main.get("timezone", "-"))

        # Network
        c = card(self.summary_frame, "🌐 Jaringan")
        row(c, "ISP",      geo_main.get("isp", "-"))
        row(c, "Org",      geo_main.get("organisasi", "-"))
        row(c, "Hostname", rdns.get("hostname", "-"))
        asn0 = asns[0] if asns else {}
        row(c, "ASN", f"AS{asn0.get('asn', '-')} — {asn0.get('nama', '-')}")
        row(c, "Mobile",  "Ya" if geo_main.get("mobile")  else "Tidak")
        row(c, "Proxy",   "Ya" if geo_main.get("proxy")   else "Tidak")
        row(c, "Hosting", "Ya" if geo_main.get("hosting") else "Tidak")

        # Files
        maps = data_all.get("maps", {})
        c = card(self.summary_frame, "📁 File Output")
        row(c, "Folder",     self.output_folder)
        row(c, "Peta HTML",  maps.get("map_file", "-"))
        row(c, "Google Maps", maps.get("google_maps_url", "-"))
        row(c, "PDF",        data_all.get("pdf", "-"))

        # Open folder button
        btn_open = tk.Button(self.summary_frame, text="📂  Buka Folder Output",
                             command=self._open_output_folder,
                             font=FONT, bg=PANEL, fg=ACCENT,
                             activebackground=BORDER, activeforeground=ACCENT,
                             relief="flat", cursor="hand2", padx=16, pady=8)
        btn_open.pack(pady=(10, 16))

        self.notebook.select(1)  # Switch ke tab summary

    def _open_output_folder(self):
        if self.output_folder and os.path.exists(self.output_folder):
            if sys.platform == "win32":
                os.startfile(self.output_folder)
            elif sys.platform == "darwin":
                os.system(f'open "{self.output_folder}"')
            else:
                os.system(f'xdg-open "{self.output_folder}"')

    # ── LOG HELPERS ───────────────────────────────────────────────────────────

    def log(self, text, tag=None):
        def _insert():
            self.output_text.configure(state="normal")
            if tag:
                self.output_text.insert("end", text + "\n", tag)
            else:
                self.output_text.insert("end", text + "\n")
            self.output_text.see("end")
            self.output_text.configure(state="disabled")
        self.root.after(0, _insert)

    def log_section(self, title):
        self.log(f"\n{'─'*55}", "muted")
        self.log(f"  {title}", "header")
        self.log(f"{'─'*55}", "muted")

    def log_dict(self, d, indent=4):
        skip = ("lat", "lon", "_score", "_level_color")
        pad  = " " * indent
        for k, v in d.items():
            if k in skip:
                continue
            if isinstance(v, dict):
                self.log(f"{pad}{k}:")
                self.log_dict(v, indent + 4)
            elif isinstance(v, list):
                self.log(f"{pad}{k}:")
                for item in v:
                    if isinstance(item, dict):
                        for ik, iv in item.items():
                            self.log(f"{pad}    {ik}: {iv}")
                    else:
                        self.log(f"{pad}    - {item}")
            else:
                self.log(f"{pad}{k:28s}: {v}")

    def set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app  = IPTrackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
