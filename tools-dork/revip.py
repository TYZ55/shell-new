#!/usr/bin/env python3
"""
TAF3 - Reverse IP & Domain to IP Tool
GUI dark neon style
Logic: sama persis dengan script asli
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import re
import socket
import os
import warnings
from multiprocessing.dummy import Pool
from datetime import datetime

warnings.filterwarnings('ignore')

# ─── TEMA ────────────────────────────────────────────────────────
BG        = "#0a0a0f"
BG2       = "#0f0f1a"
BG3       = "#13131f"
PANEL     = "#16161f"
BORDER    = "#1e1e2e"
NEON_CYAN = "#00f5ff"
NEON_PINK = "#ff2d78"
NEON_PURP = "#9b59b6"
NEON_ORAN = "#ff6b35"
NEON_GREE = "#00ff88"
NEON_YELL = "#ffd700"
TEXT      = "#e0e0f0"
TEXT_DIM  = "#6272a4"

FONT_MONO = ("Consolas", 10)
FONT_TITL = ("Consolas", 16, "bold")
FONT_SMOL = ("Consolas", 9)
FONT_BIG  = ("Consolas", 11)

BANNER_ART = (
    "  ██████╗ ███████╗██╗   ██╗██╗██████╗ ",
    "  ██╔══██╗██╔════╝██║   ██║██║██╔══██╗",
    "  ██████╔╝█████╗  ██║   ██║██║██████╔╝",
    "  ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║██╔═══╝ ",
    "  ██║  ██║███████╗ ╚████╔╝ ██║██║     ",
    "  ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚═╝     ",
)


class GlowButton(tk.Canvas):
    def __init__(self, parent, text, command=None, color=NEON_CYAN,
                 width=160, height=36, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=BG2, highlightthickness=0, **kwargs)
        self.command = command
        self.color   = color
        self.text    = text
        self._draw(False)
        self.bind("<Enter>",    lambda e: self._draw(True))
        self.bind("<Leave>",    lambda e: self._draw(False))
        self.bind("<Button-1>", lambda e: command() if command else None)

    def _draw(self, hover):
        self.delete("all")
        w, h = int(self["width"]), int(self["height"])
        fill = "#1a1a2e" if hover else "#12121c"
        self.create_rectangle(2, 2, w-2, h-2, fill=fill,
                               outline=self.color, width=2 if hover else 1)
        if hover:
            self.create_rectangle(1, 1, w-1, h-1, fill="",
                                   outline=self.color + "44", width=3)
        self.create_text(w//2, h//2, text=self.text,
                         fill="white" if hover else self.color,
                         font=("Consolas", 10, "bold"))


class RevIPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("◈ REVIP TOOL — Reverse IP & Domain to IP ◈")
        self.geometry("1180x760")
        self.configure(bg=BG)
        self.resizable(True, True)

        self.running     = False
        self._stop_flag  = False
        self.results     = []          # list of (type, ip_or_domain, found)

        self._build_ui()

    # ─── HELPERS ─────────────────────────────────────────────────
    def _section(self, parent, title, color=NEON_CYAN):
        f = tk.Frame(parent, bg=BG2,
                     highlightbackground=color, highlightthickness=1)
        f.pack(fill="x", pady=4)
        tk.Label(f, text=f"  {title}", font=("Consolas", 10, "bold"),
                 fg=color, bg=BG2, anchor="w").pack(fill="x", padx=6, pady=(6,2))
        return f

    def _label_entry(self, parent, label, fg=NEON_CYAN):
        tk.Label(parent, text=label, font=FONT_SMOL, fg=TEXT_DIM,
                 bg=BG2, anchor="w").pack(fill="x", padx=8)
        var = tk.StringVar()
        e = tk.Entry(parent, textvariable=var, bg=BG3, fg=fg,
                     insertbackground=fg, font=FONT_MONO,
                     relief="flat", bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=fg)
        e.pack(fill="x", padx=8, pady=(0,6), ipady=5)
        return var

    # ─── BUILD UI ────────────────────────────────────────────────
    def _build_ui(self):
        # Header / banner
        hdr = tk.Frame(self, bg=BG, pady=8)
        hdr.pack(fill="x", padx=20)
        for i, line in enumerate(BANNER_ART):
            c = NEON_CYAN if i < 3 else NEON_PURP
            tk.Label(hdr, text=line, font=("Consolas", 9, "bold"),
                     fg=c, bg=BG).pack(anchor="w")
        info = tk.Frame(hdr, bg=BG)
        info.pack(anchor="w", pady=(4,0))
        tk.Label(info, text="  Reverse IP & Domain-to-IP Tool",
                 font=("Consolas", 10), fg=NEON_GREE, bg=BG).pack(side="left")
        tk.Label(info, text="  |  3 API Sources",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG).pack(side="left")

        tk.Frame(self, bg=NEON_CYAN, height=1).pack(fill="x", padx=20)

        # Notebook tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=8)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=TEXT_DIM,
                        font=FONT_MONO, padding=[16, 7])
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL)],
                  foreground=[("selected", NEON_CYAN)])

        t1 = tk.Frame(nb, bg=BG)
        nb.add(t1, text="  🔁  REVERSE IP  ")
        t2 = tk.Frame(nb, bg=BG)
        nb.add(t2, text="  🌐  DOMAIN → IP  ")

        self._build_revip_tab(t1)
        self._build_d2ip_tab(t2)

        # Shared log di bawah tabs
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="x", padx=20, pady=(0,4))
        tk.Label(log_frame, text="📡 LIVE LOG", font=("Consolas",10,"bold"),
                 fg=NEON_CYAN, bg=BG).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(
            log_frame, bg=BG2, fg=TEXT, font=FONT_SMOL,
            height=8, wrap="word", relief="flat", bd=0, state="disabled")
        self.log.pack(fill="x")
        for tag, col in [("cyan", NEON_CYAN), ("pink", NEON_PINK),
                         ("green", NEON_GREE), ("yell", NEON_YELL),
                         ("dim", TEXT_DIM), ("oran", NEON_ORAN), ("purp", NEON_PURP)]:
            self.log.tag_config(tag, foreground=col)

        # Status bar
        self.status_var = tk.StringVar(value="● SIAP")
        sb = tk.Frame(self, bg=BORDER, pady=3)
        sb.pack(fill="x", side="bottom")
        tk.Label(sb, textvariable=self.status_var,
                 font=FONT_SMOL, fg=NEON_GREE, bg=BORDER).pack(side="left", padx=12)
        self.count_var = tk.StringVar(value="Hasil: 0")
        tk.Label(sb, textvariable=self.count_var,
                 font=FONT_SMOL, fg=NEON_YELL, bg=BORDER).pack(side="right", padx=12)

    # ─── TAB 1: REVERSE IP ───────────────────────────────────────
    def _build_revip_tab(self, parent):
        main = tk.Frame(parent, bg=BG)
        main.pack(fill="both", expand=True, padx=4, pady=4)

        # Left panel
        left = tk.Frame(main, bg=BG, width=340)
        left.pack(side="left", fill="y", padx=(0,10))
        left.pack_propagate(False)

        s1 = self._section(left, "⚙ INPUT", NEON_PINK)
        tk.Label(s1, text="  File berisi list IP (1 IP per baris):",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w", padx=8)
        fp_frame = tk.Frame(s1, bg=BG2)
        fp_frame.pack(fill="x", padx=8, pady=(0,6))
        self.revip_file_var = tk.StringVar()
        tk.Entry(fp_frame, textvariable=self.revip_file_var, bg=BG3,
                 fg=NEON_PINK, insertbackground=NEON_PINK, font=FONT_MONO,
                 relief="flat", highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=NEON_PINK).pack(side="left", fill="x", expand=True, ipady=4)
        GlowButton(fp_frame, "📂", command=self._browse_revip_file,
                   color=NEON_PINK, width=38, height=30).pack(side="right", padx=(4,0))

        s2 = self._section(left, "🔧 THREADS", NEON_YELL)
        tf = tk.Frame(s2, bg=BG2)
        tf.pack(fill="x", padx=8, pady=4)
        tk.Label(tf, text="Thread (disarankan rendah):",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(side="left")
        self.revip_thread_var = tk.IntVar(value=5)
        tk.Spinbox(tf, from_=1, to=50, textvariable=self.revip_thread_var,
                   bg=BG3, fg=NEON_YELL, width=5, font=FONT_SMOL,
                   buttonbackground=BG3).pack(side="right")
        tk.Label(s2, text="  ℹ Makin rendah = hasil makin akurat",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w", padx=8, pady=(0,6))

        s3 = self._section(left, "📡 API SOURCES", NEON_PURP)
        for api, color in [("API 1 — RapidDNS", NEON_GREE),
                            ("API 2 — WebScan.cc", NEON_CYAN),
                            ("API 3 — xreverselabs", NEON_ORAN)]:
            tk.Label(s3, text=f"  ✓ {api}", font=FONT_SMOL, fg=color, bg=BG2).pack(anchor="w", padx=8)
        tk.Label(s3, text="", bg=BG2).pack()

        bf = tk.Frame(left, bg=BG)
        bf.pack(fill="x", pady=8)
        GlowButton(bf, "▶ MULAI REVERSE IP",
                   command=self._start_revip, color=NEON_GREE, width=330, height=42).pack(pady=3)
        GlowButton(bf, "⏹ STOP",
                   command=self._stop, color=NEON_PINK, width=330, height=32).pack(pady=3)
        GlowButton(bf, "💾 Simpan Hasil",
                   command=lambda: self._save_results("revip"), color=NEON_CYAN, width=330, height=32).pack(pady=3)

        # Right: hasil
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="🌐 DOMAIN DITEMUKAN", font=("Consolas",10,"bold"),
                 fg=NEON_GREE, bg=BG).pack(anchor="w")

        sf = tk.Frame(right, bg=BG2)
        sf.pack(fill="x", pady=(2,0))
        tk.Label(sf, text="Filter:", font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(side="left", padx=6)
        self.revip_filter = tk.StringVar()
        self.revip_filter.trace("w", lambda *a: self._filter_box(self.revip_box, self.revip_domains, self.revip_filter))
        tk.Entry(sf, textvariable=self.revip_filter, bg=BG3, fg=NEON_GREE,
                 insertbackground=NEON_GREE, font=FONT_SMOL, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=NEON_GREE).pack(side="left", fill="x", expand=True, padx=6, ipady=3)

        self.revip_box = scrolledtext.ScrolledText(
            right, bg=BG2, fg=NEON_GREE, font=FONT_SMOL,
            wrap="none", relief="flat", bd=0, state="disabled")
        self.revip_box.pack(fill="both", expand=True, pady=4)
        self.revip_domains = []   # list untuk filter

    # ─── TAB 2: DOMAIN → IP ──────────────────────────────────────
    def _build_d2ip_tab(self, parent):
        main = tk.Frame(parent, bg=BG)
        main.pack(fill="both", expand=True, padx=4, pady=4)

        left = tk.Frame(main, bg=BG, width=340)
        left.pack(side="left", fill="y", padx=(0,10))
        left.pack_propagate(False)

        s1 = self._section(left, "⚙ INPUT", NEON_CYAN)
        tk.Label(s1, text="  File berisi list Domain (1 domain per baris):",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w", padx=8)
        fp2 = tk.Frame(s1, bg=BG2)
        fp2.pack(fill="x", padx=8, pady=(0,6))
        self.d2ip_file_var = tk.StringVar()
        tk.Entry(fp2, textvariable=self.d2ip_file_var, bg=BG3,
                 fg=NEON_CYAN, insertbackground=NEON_CYAN, font=FONT_MONO,
                 relief="flat", highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=NEON_CYAN).pack(side="left", fill="x", expand=True, ipady=4)
        GlowButton(fp2, "📂", command=self._browse_d2ip_file,
                   color=NEON_CYAN, width=38, height=30).pack(side="right", padx=(4,0))

        s2 = self._section(left, "🔧 THREADS", NEON_YELL)
        tf2 = tk.Frame(s2, bg=BG2)
        tf2.pack(fill="x", padx=8, pady=4)
        tk.Label(tf2, text="Thread (rekomen 300):",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(side="left")
        self.d2ip_thread_var = tk.IntVar(value=50)
        tk.Spinbox(tf2, from_=1, to=500, textvariable=self.d2ip_thread_var,
                   bg=BG3, fg=NEON_YELL, width=6, font=FONT_SMOL,
                   buttonbackground=BG3).pack(side="right")
        tk.Label(s2, text="", bg=BG2).pack()

        s3 = self._section(left, "ℹ INFO", NEON_PURP)
        tk.Label(s3, text="  Resolve domain → IP menggunakan\n  socket.gethostbyname()",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2, justify="left").pack(anchor="w", padx=8, pady=(0,6))

        bf2 = tk.Frame(left, bg=BG)
        bf2.pack(fill="x", pady=8)
        GlowButton(bf2, "▶ MULAI DOMAIN → IP",
                   command=self._start_d2ip, color=NEON_GREE, width=330, height=42).pack(pady=3)
        GlowButton(bf2, "⏹ STOP",
                   command=self._stop, color=NEON_PINK, width=330, height=32).pack(pady=3)
        GlowButton(bf2, "💾 Simpan Hasil",
                   command=lambda: self._save_results("d2ip"), color=NEON_CYAN, width=330, height=32).pack(pady=3)

        right2 = tk.Frame(main, bg=BG)
        right2.pack(side="left", fill="both", expand=True)

        # Treeview untuk Domain → IP
        tk.Label(right2, text="🖥 HASIL RESOLVE", font=("Consolas",10,"bold"),
                 fg=NEON_CYAN, bg=BG).pack(anchor="w")

        cols = ("No", "Domain", "IP", "Status")
        self.d2ip_tree = ttk.Treeview(right2, columns=cols, show="headings")
        style = ttk.Style()
        style.configure("Treeview", background=BG2, foreground=TEXT,
                        fieldbackground=BG2, font=FONT_SMOL, rowheight=22)
        style.configure("Treeview.Heading", background=PANEL,
                        foreground=NEON_CYAN, font=("Consolas",10,"bold"))
        style.map("Treeview", background=[("selected", BG3)],
                  foreground=[("selected", NEON_CYAN)])
        for c, w in zip(cols, [40, 340, 200, 120]):
            self.d2ip_tree.heading(c, text=c)
            self.d2ip_tree.column(c, width=w, minwidth=30)
        sy = ttk.Scrollbar(right2, orient="vertical", command=self.d2ip_tree.yview)
        sx = ttk.Scrollbar(right2, orient="horizontal", command=self.d2ip_tree.xview)
        self.d2ip_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        self.d2ip_tree.pack(fill="both", expand=True, pady=4)

        self.d2ip_results = []   # [(domain, ip)]

    # ─── BROWSE ──────────────────────────────────────────────────
    def _browse_revip_file(self):
        p = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.revip_file_var.set(p)

    def _browse_d2ip_file(self):
        p = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.d2ip_file_var.set(p)

    # ─── LOG ─────────────────────────────────────────────────────
    def _log(self, msg, tag=""):
        self.log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] ", "dim")
        self.log.insert("end", msg + "\n", tag or "")
        self.log.see("end")
        self.log.config(state="disabled")

    def _status(self, msg):
        self.status_var.set(f"● {msg}")

    # ─── FILTER BOX ──────────────────────────────────────────────
    def _filter_box(self, box, data, var):
        kw = var.get().lower()
        box.config(state="normal")
        box.delete("1.0", "end")
        for item in data:
            if kw in item.lower():
                box.insert("end", item + "\n")
        box.config(state="disabled")

    # ─── REVERSE IP LOGIC (sama dengan asli) ─────────────────────
    def _start_revip(self):
        if self.running:
            return
        path = self.revip_file_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("File", "Pilih file list IP yang valid!")
            return
        with open(path, errors="ignore") as f:
            ips = [l.strip() for l in f if l.strip()]
        if not ips:
            messagebox.showwarning("File", "File kosong!")
            return
        threading.Thread(target=self._run_revip, args=(ips,), daemon=True).start()

    def _run_revip(self, ips):
        self.running = True
        self._stop_flag = False
        threads = self.revip_thread_var.get()
        self.revip_domains.clear()

        self._log(f"▶ Reverse IP — {len(ips)} IP, {threads} thread", "cyan")
        self._status(f"Reverse IP... {len(ips)} target")

        def process(ip):
            if self._stop_flag:
                return
            self._api1(ip)
            self._api2(ip)
            self._api3(ip)

        pool = Pool(threads)
        pool.map(process, ips)
        pool.close()
        pool.join()

        self._log(f"✅ Selesai! Total domain: {len(self.revip_domains)}", "green")
        self._status(f"Selesai — {len(self.revip_domains)} domain")
        self.count_var.set(f"Hasil: {len(self.revip_domains)}")
        self.running = False

    def _add_revip_domain(self, ip, domain, api_label):
        if domain not in self.revip_domains:
            self.revip_domains.append(domain)
            self.revip_box.config(state="normal")
            self.revip_box.insert("end", domain + "\n")
            self.revip_box.see("end")
            self.revip_box.config(state="disabled")
            self.count_var.set(f"Hasil: {len(self.revip_domains)}")
            self._log(f"[{api_label}] {ip} → {domain}", "oran")

    def _api1(self, ip):
        try:
            url = f"https://rapiddns.io/s/{ip}?full=1&down=1#result"
            data = requests.get(url, timeout=10, verify=False).text
            getlist = re.findall(
                r'<td>(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z]{1,63}</td>',
                data)[3:]
            for d in getlist:
                dl = d.lower()
                skip = ('result','total','webmail.','ftp.','cpanel.',
                        'webdisk.','cpcalendars.','mail.','cpcontacts.','ns1.','ns2.')
                if any(s in dl for s in skip[:2]) or any(dl.startswith(s) for s in skip[2:]):
                    continue
                d = d.replace('www.','').replace('<td>','').replace('</td>','')
                self.after(0, self._add_revip_domain, ip, d, "API1-RapidDNS")
                with open("Grabbed.txt", "a") as f:
                    f.write(d + "\n")
        except:
            pass

    def _api2(self, ip):
        try:
            url = f"https://api.webscan.cc/?action=query&ip={ip}"
            data = requests.get(url, timeout=10, verify=False).text
            getlist = re.findall(r'"domain": "(.*?)",', data)[3:]
            for d in getlist:
                dl = d.lower()
                skip = ('result','total','webmail.','ftp.','cpanel.',
                        'webdisk.','cpcalendars.','mail.','cpcontacts.','ns1.','ns2.')
                if any(s in dl for s in skip[:2]) or any(dl.startswith(s) for s in skip[2:]):
                    continue
                d = d.replace('www.','')
                self.after(0, self._add_revip_domain, ip, d, "API2-WebScan")
                with open("Grabbed.txt", "a") as f:
                    f.write(d + "\n")
        except:
            pass

    def _api3(self, ip):
        try:
            url = f"http://main-srv.xreverselabs.my.id:1337/reverse-ip?apikey=unknown&ip={ip}"
            data = requests.get(url, timeout=10).text
            getlist = re.findall(r'"(.*?)"', data)[3:]
            for d in getlist:
                dl = d.lower()
                skip = ('status','success','Domains','webmail.','ftp.','cpanel.',
                        'webdisk.','cpcalendars.','mail.','cpcontacts.','ns1.','ns2.')
                if any(s in dl for s in skip[:3]) or any(dl.startswith(s) for s in skip[3:]):
                    continue
                d = d.replace('www.','').replace('Domains','')
                self.after(0, self._add_revip_domain, ip, d, "API3-xRevLabs")
                with open("Grabbed.txt", "a") as f:
                    f.write(d + "\n")
        except:
            pass

    # ─── DOMAIN → IP LOGIC (sama dengan asli) ────────────────────
    def _start_d2ip(self):
        if self.running:
            return
        path = self.d2ip_file_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("File", "Pilih file list domain yang valid!")
            return
        with open(path, errors="ignore") as f:
            domains = [l.strip() for l in f if l.strip()]
        if not domains:
            messagebox.showwarning("File", "File kosong!")
            return
        threading.Thread(target=self._run_d2ip, args=(domains,), daemon=True).start()

    def _run_d2ip(self, domains):
        self.running = True
        self._stop_flag = False
        threads = self.d2ip_thread_var.get()
        self.d2ip_results.clear()
        self.d2ip_tree.delete(*self.d2ip_tree.get_children())

        self._log(f"▶ Domain→IP — {len(domains)} domain, {threads} thread", "cyan")
        self._status(f"Resolving {len(domains)} domain...")

        counter = [0]

        def clean_domain(site):
            site = re.sub(r'^https?://', '', site)
            site = site.replace('www.', '')
            site = site.split('/')[0].rstrip('/')
            return site

        def resolve(raw):
            if self._stop_flag:
                return
            try:
                dom = clean_domain(raw)
                try:
                    ip = socket.gethostbyname(dom)
                    self.d2ip_results.append((dom, ip))
                    counter[0] += 1
                    self.after(0, self._add_d2ip_row, counter[0], dom, ip, "✓ OK")
                    self._log(f"{dom} → {ip}", "green")
                    with open("IPs.txt", "a") as f:
                        f.write(ip + "\n")
                except Exception:
                    counter[0] += 1
                    self.after(0, self._add_d2ip_row, counter[0], dom, "-", "✗ Gagal")
                    self._log(f"{dom} → [tidak resolve]", "dim")
            except Exception:
                pass

        pool = Pool(threads)
        pool.map(resolve, domains)
        pool.close()
        pool.join()

        ok = len(self.d2ip_results)
        self._log(f"✅ Selesai! {ok}/{len(domains)} berhasil resolve", "green")
        self._status(f"Selesai — {ok} IP ditemukan")
        self.count_var.set(f"Hasil: {ok}")
        self.running = False

    def _add_d2ip_row(self, n, domain, ip, status):
        tag = "ok" if "OK" in status else "fail"
        iid = self.d2ip_tree.insert("", "end", values=(n, domain, ip, status))
        # Warna berdasar status
        self.d2ip_tree.tag_configure("ok",   foreground=NEON_GREE)
        self.d2ip_tree.tag_configure("fail", foreground=NEON_PINK)
        self.d2ip_tree.item(iid, tags=(tag,))
        self.d2ip_tree.see(iid)

    # ─── STOP ────────────────────────────────────────────────────
    def _stop(self):
        self._stop_flag = True
        self._status("Menghentikan...")

    # ─── SAVE ────────────────────────────────────────────────────
    def _save_results(self, mode):
        if mode == "revip":
            data = self.revip_domains
            default = f"revip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            if not data:
                messagebox.showinfo("Simpan", "Belum ada hasil reverse IP.")
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text", "*.txt")],
                initialfile=default)
            if not path:
                return
            with open(path, "w") as f:
                for d in sorted(data):
                    f.write(d + "\n")
        else:
            data = self.d2ip_results
            default = f"ip_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            if not data:
                messagebox.showinfo("Simpan", "Belum ada hasil resolve.")
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text", "*.txt")],
                initialfile=default)
            if not path:
                return
            with open(path, "w") as f:
                for dom, ip in data:
                    f.write(f"{dom},{ip}\n")

        self._log(f"✅ Disimpan: {path}", "green")
        messagebox.showinfo("Simpan", f"Tersimpan:\n{path}")


if __name__ == "__main__":
    app = RevIPApp()
    app.mainloop()
