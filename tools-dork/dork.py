#!/usr/bin/env python3
"""
Google Dork Audit Tool
API: Serper.dev (2,500 query gratis/bulan)
Untuk: Audit domain
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import json
import time
import webbrowser
import csv
from datetime import datetime

# ─── WARNA TEMA NEON ──────────────────────────────────────────────
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
TEXT_MUTED= "#44475a"

FONT_MONO = ("Consolas", 10)
FONT_HEAD = ("Consolas", 13, "bold")
FONT_TITL = ("Consolas", 18, "bold")
FONT_SMOL = ("Consolas", 9)

# ─── TEMPLATE DORK ────────────────────────────────────────────────
DORK_TEMPLATES = {
    "📁 Exposed Files": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:txt',
        'site:{domain} filetype:log',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:bak',
        'site:{domain} filetype:env',
        'site:{domain} filetype:config',
    ],
    "🔐 Login / Admin Pages": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:phpmyadmin',
        'site:{domain} inurl:webmail',
    ],
    "⚠️ Sensitive Info": [
        'site:{domain} "password" filetype:txt',
        'site:{domain} "username" filetype:txt',
        'site:{domain} intext:"Index of /"',
        'site:{domain} "config.php" intitle:"index of"',
        'site:{domain} "db_password" OR "db_user"',
        'site:{domain} inurl:".git" intitle:"index of"',
    ],
    "📧 Exposed Email / Contact": [
        'site:{domain} intext:"@{domain}"',
        'site:{domain} intext:"email" filetype:txt',
        'site:{domain} inurl:contact',
    ],
    "🗂️ Directory Listing": [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of /" "parent directory"',
        'site:{domain} intitle:"directory listing"',
    ],
    "🔧 Tech Stack Info": [
        'site:{domain} inurl:wp-content',
        'site:{domain} inurl:wp-includes',
        'site:{domain} inurl:"/vendor/" filetype:php',
        'site:{domain} inurl:".env"',
        'site:{domain} inurl:"phpinfo.php"',
        'site:{domain} "powered by" intext:WordPress OR Joomla OR Drupal',
    ],
    "🎓 .EDU Specific": [
        'site:.edu "{domain}" filetype:pdf',
        'site:.edu "{domain}" inurl:admin',
        'site:.edu "{domain}" "student" filetype:xls',
        'site:.edu filetype:sql',
        'site:.edu intitle:"index of" "backup"',
    ],
}


class GlowButton(tk.Canvas):
    def __init__(self, parent, text, command=None, color=NEON_CYAN,
                 width=160, height=36, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=BG2, highlightthickness=0, **kwargs)
        self.command = command
        self.color = color
        self.text = text
        self._draw(False)
        self.bind("<Enter>", lambda e: self._draw(True))
        self.bind("<Leave>", lambda e: self._draw(False))
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
        fg = "white" if hover else self.color
        self.create_text(w//2, h//2, text=self.text, fill=fg,
                         font=("Consolas", 10, "bold"))


class DorkResult:
    def __init__(self, title, url, snippet, dork_used):
        self.title   = title
        self.url     = url
        self.snippet = snippet
        self.dork_used = dork_used
        self.timestamp = datetime.now().strftime("%H:%M:%S")


class GoogleDorker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("◈ GOOGLE DORK AUDIT TOOL — By SHIBAL SEKYIYA 🌐")
        self.geometry("1280x840")
        self.configure(bg=BG)
        self.resizable(True, True)

        self.api_key      = tk.StringVar()
        self.domain       = tk.StringVar()
        self.custom_dork  = tk.StringVar()
        self.delay        = tk.DoubleVar(value=1.0)
        self.num_results  = tk.IntVar(value=10)
        self.results      = []
        self.running      = False
        self._stop_flag   = False

        self._build_ui()

    # ─── UI ───────────────────────────────────────────────────────
    def _section(self, parent, title, color=NEON_CYAN):
        f = tk.Frame(parent, bg=BG2, highlightbackground=color,
                     highlightthickness=1)
        f.pack(fill="x", pady=4)
        tk.Label(f, text=f"  {title}", font=("Consolas", 10, "bold"),
                 fg=color, bg=BG2, anchor="w").pack(fill="x", padx=6, pady=(6,2))
        return f

    def _entry(self, parent, label, var, show=None, fg=NEON_CYAN):
        tk.Label(parent, text=label, font=FONT_SMOL, fg=TEXT_DIM,
                 bg=BG2, anchor="w").pack(fill="x", padx=8)
        e = tk.Entry(parent, textvariable=var, bg=BG3, fg=fg,
                     insertbackground=fg, font=FONT_MONO,
                     relief="flat", bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=fg,
                     show=show or "")
        e.pack(fill="x", padx=8, pady=(0,6), ipady=5)
        return e

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=BG, pady=10)
        hdr.pack(fill="x", padx=20)
        tk.Label(hdr, text="◈ GOOGLE DORK AUDIT TOOL ◈",
                 font=FONT_TITL, fg=NEON_CYAN, bg=BG).pack(side="left")
        tk.Label(hdr, text="  powered by Shibal Sekiya  |  Use Your API with Serper.dev",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG).pack(side="left", pady=6)

        tk.Frame(self, bg=NEON_CYAN, height=1).pack(fill="x", padx=20)

        # ── Layout ──
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=20, pady=8)

        left = tk.Frame(main, bg=BG, width=380)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_left(left)
        self._build_right(right)

        # ── Status bar ──
        self.status_var = tk.StringVar(value="● SIAP")
        sb = tk.Frame(self, bg=BORDER, pady=4)
        sb.pack(fill="x", side="bottom")
        tk.Label(sb, textvariable=self.status_var,
                 font=FONT_SMOL, fg=NEON_GREE, bg=BORDER).pack(side="left", padx=12)
        self.count_var = tk.StringVar(value="Hasil: 0")
        tk.Label(sb, textvariable=self.count_var,
                 font=FONT_SMOL, fg=NEON_YELL, bg=BORDER).pack(side="right", padx=12)
        self.quota_var = tk.StringVar(value="Quota: -")
        tk.Label(sb, textvariable=self.quota_var,
                 font=FONT_SMOL, fg=NEON_PURP, bg=BORDER).pack(side="right", padx=12)

    def _build_left(self, parent):
        # ── API Config ──
        s1 = self._section(parent, "⚙ SERPER.DEV API", NEON_PURP)
        self._entry(s1, "API Key (serper.dev):", self.api_key, show="*", fg=NEON_PURP)

        info = tk.Frame(s1, bg=BG2)
        info.pack(fill="x", padx=8, pady=(0,4))
        tk.Label(info, text="✓ Gratis 2,500 query/bulan (tidak perlu CC)",
                 font=FONT_SMOL, fg=NEON_GREE, bg=BG2).pack(anchor="w")
        tk.Label(info, text="✓ Hasil Google real, JSON bersih",
                 font=FONT_SMOL, fg=NEON_GREE, bg=BG2).pack(anchor="w")
        tk.Label(info, text="✓ Daftar di: serper.dev",
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w")

        GlowButton(s1, "🌐 Buka serper.dev",
                   command=lambda: webbrowser.open("https://serper.dev"),
                   color=NEON_PURP, width=358, height=30).pack(padx=8, pady=6)

        # ── Target ──
        s2 = self._section(parent, "🎯 TARGET DOMAIN", NEON_PINK)
        self._entry(s2, "Domain target (contoh: kampus.ac.id):",
                    self.domain, fg=NEON_PINK)

        # ── Custom Dork ──
        s3 = self._section(parent, "✏ CUSTOM DORK MANUAL", NEON_ORAN)
        self._entry(s3, "Dork query — gunakan {domain} sebagai placeholder:",
                    self.custom_dork, fg=NEON_ORAN)
        tk.Label(s3, text='  Contoh: site:{domain} filetype:sql "backup"',
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w", padx=8)
        tk.Label(s3, text='  Contoh: site:{domain} "NIM" OR "NPM" filetype:xls',
                 font=FONT_SMOL, fg=TEXT_DIM, bg=BG2).pack(anchor="w", padx=8, pady=(0,6))

        # ── Template Dork ──
        s4 = self._section(parent, "📋 TEMPLATE DORK", NEON_GREE)
        self.template_var = tk.StringVar(value=list(DORK_TEMPLATES.keys())[0])
        for cat in DORK_TEMPLATES:
            rb = tk.Radiobutton(s4, text=cat, variable=self.template_var, value=cat,
                                bg=BG2, fg=TEXT, selectcolor=BG3,
                                activebackground=BG2, activeforeground=NEON_GREE,
                                font=FONT_SMOL)
            rb.pack(anchor="w", padx=12)

        # ── Settings ──
        s5 = self._section(parent, "🔧 PENGATURAN", NEON_YELL)
        rf = tk.Frame(s5, bg=BG2)
        rf.pack(fill="x", padx=8, pady=2)
        tk.Label(rf, text="Hasil per query (max 100):", font=FONT_SMOL,
                 fg=TEXT_DIM, bg=BG2).pack(side="left")
        tk.Spinbox(rf, from_=10, to=100, increment=10, textvariable=self.num_results,
                   bg=BG3, fg=NEON_YELL, width=5, font=FONT_SMOL,
                   buttonbackground=BG3).pack(side="right", padx=4)

        df = tk.Frame(s5, bg=BG2)
        df.pack(fill="x", padx=8, pady=2)
        tk.Label(df, text="Delay antar query (detik):", font=FONT_SMOL,
                 fg=TEXT_DIM, bg=BG2).pack(side="left")
        tk.Scale(df, from_=0.0, to=5.0, resolution=0.5,
                 variable=self.delay, orient="horizontal",
                 bg=BG2, fg=NEON_YELL, troughcolor=BG3,
                 highlightthickness=0, length=140).pack(side="right")

        # ── Buttons ──
        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", pady=8)
        GlowButton(bf, "▶ JALANKAN SEMUA TEMPLATE",
                   command=self._run_templates, color=NEON_GREE, width=375, height=40).pack(pady=3)
        GlowButton(bf, "✏ JALANKAN DORK MANUAL",
                   command=self._run_custom, color=NEON_ORAN, width=375, height=38).pack(pady=3)
        GlowButton(bf, "⏹ STOP",
                   command=self._stop, color=NEON_PINK, width=375, height=32).pack(pady=3)

    def _build_right(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=TEXT_DIM,
                        font=FONT_MONO, padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL)],
                  foreground=[("selected", NEON_CYAN)])

        # Tab 1 – Live Log
        t1 = tk.Frame(nb, bg=BG)
        nb.add(t1, text="📡  LIVE LOG")
        self.log = scrolledtext.ScrolledText(
            t1, bg=BG2, fg=TEXT, font=FONT_MONO,
            insertbackground=NEON_CYAN, wrap="word",
            relief="flat", bd=0, state="disabled")
        self.log.pack(fill="both", expand=True, padx=4, pady=4)
        for tag, col in [("cyan", NEON_CYAN), ("pink", NEON_PINK),
                         ("green", NEON_GREE), ("yell", NEON_YELL),
                         ("dim", TEXT_DIM), ("oran", NEON_ORAN), ("purp", NEON_PURP)]:
            self.log.tag_config(tag, foreground=col)

        # Tab 2 – Hasil
        t2 = tk.Frame(nb, bg=BG)
        nb.add(t2, text="📊  HASIL")
        cols = ("No", "Title", "URL", "Dork", "Waktu")
        self.tree = ttk.Treeview(t2, columns=cols, show="headings")
        style.configure("Treeview", background=BG2, foreground=TEXT,
                        fieldbackground=BG2, font=FONT_SMOL, rowheight=22)
        style.configure("Treeview.Heading", background=PANEL,
                        foreground=NEON_CYAN, font=("Consolas", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", BG3)],
                  foreground=[("selected", NEON_CYAN)])
        for c, w in zip(cols, [40, 320, 400, 260, 70]):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, minwidth=30)
        sy = ttk.Scrollbar(t2, orient="vertical", command=self.tree.yview)
        sx = ttk.Scrollbar(t2, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._open_url)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        # Tab 3 – Detail
        t3 = tk.Frame(nb, bg=BG)
        nb.add(t3, text="🔍  DETAIL")
        self.detail = scrolledtext.ScrolledText(
            t3, bg=BG2, fg=TEXT, font=FONT_MONO,
            wrap="word", relief="flat", bd=0)
        self.detail.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 4 – Dork List
        t4 = tk.Frame(nb, bg=BG)
        nb.add(t4, text="📋  DORK LIST")
        self._build_dork_list(t4)

        # Action bar
        af = tk.Frame(parent, bg=BG)
        af.pack(fill="x", pady=4)
        GlowButton(af, "💾 Export CSV",   command=self._export_csv,
                   color=NEON_GREE, width=175, height=32).pack(side="left", padx=4)
        GlowButton(af, "💾 Export JSON",  command=self._export_json,
                   color=NEON_CYAN, width=175, height=32).pack(side="left", padx=4)
        GlowButton(af, "🌐 Buka Terpilih",command=self._open_selected,
                   color=NEON_ORAN, width=175, height=32).pack(side="left", padx=4)
        GlowButton(af, "🗑 Bersihkan",    command=self._clear,
                   color=NEON_PINK, width=175, height=32).pack(side="left", padx=4)

    def _build_dork_list(self, parent):
        """Tab menampilkan semua template dork."""
        txt = scrolledtext.ScrolledText(parent, bg=BG2, fg=TEXT,
                                         font=FONT_SMOL, wrap="none",
                                         relief="flat", bd=0)
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        txt.tag_config("hdr", foreground=NEON_CYAN, font=("Consolas", 10, "bold"))
        txt.tag_config("dork", foreground=NEON_ORAN)
        for cat, dorks in DORK_TEMPLATES.items():
            txt.insert("end", f"\n{cat}\n", "hdr")
            for d in dorks:
                txt.insert("end", f"  {d}\n", "dork")
        txt.config(state="disabled")

    # ─── LOG ──────────────────────────────────────────────────────
    def _log(self, msg, tag=""):
        self.log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] ", "dim")
        self.log.insert("end", msg + "\n", tag or "")
        self.log.see("end")
        self.log.config(state="disabled")

    def _status(self, msg):
        self.status_var.set(f"● {msg}")

    # ─── SERPER.DEV API ───────────────────────────────────────────
    def _search(self, query):
        key = self.api_key.get().strip()
        if not key:
            return None, "API Key kosong! Masukkan API Key serper.dev"

        url = "https://google.serper.dev/search"
        headers = {
            "X-API-KEY": key,
            "Content-Type": "application/json"
        }
        payload = {
            "q": query,
            "num": self.num_results.get(),
            "gl": "id",   # Indonesia locale
            "hl": "id",
        }
        try:
            r = requests.post(url, headers=headers,
                              data=json.dumps(payload), timeout=15)
            if r.status_code == 401:
                return None, "API Key tidak valid! Periksa kembali."
            if r.status_code == 429:
                return None, "Rate limit! Tambah delay atau tunggu sebentar."
            if r.status_code != 200:
                return None, f"HTTP Error: {r.status_code}"

            data = r.json()
            # Update quota info dari header
            credits = r.headers.get("X-API-Credits-Used", "?")
            remaining = r.headers.get("X-API-Credits-Remaining", "?")
            self.quota_var.set(f"Credits: {credits} used / {remaining} sisa")
            return data, None
        except requests.RequestException as e:
            return None, str(e)

    def _parse_results(self, data, dork):
        items = []
        # Organic results
        for item in data.get("organic", []):
            items.append(DorkResult(
                title=item.get("title", "-"),
                url=item.get("link", "-"),
                snippet=item.get("snippet", "-"),
                dork_used=dork
            ))
        return items

    # ─── RUN ──────────────────────────────────────────────────────
    def _run_templates(self):
        if self.running:
            return
        domain = self.domain.get().strip()
        if not domain:
            messagebox.showwarning("Input", "Masukkan domain target terlebih dahulu!")
            return
        cat = self.template_var.get()
        dorks = DORK_TEMPLATES.get(cat, [])
        queries = [d.replace("{domain}", domain) for d in dorks]
        threading.Thread(target=self._run_queries, args=(queries,), daemon=True).start()

    def _run_custom(self):
        if self.running:
            return
        raw = self.custom_dork.get().strip()
        if not raw:
            messagebox.showwarning("Input", "Masukkan dork manual terlebih dahulu!")
            return
        domain = self.domain.get().strip()
        query  = raw.replace("{domain}", domain)
        threading.Thread(target=self._run_queries, args=([query],), daemon=True).start()

    def _run_queries(self, queries):
        self.running = True
        self._stop_flag = False
        total = 0

        self._log("━" * 60, "dim")
        self._log(f"▶ Memulai scan: {len(queries)} query via serper.dev", "cyan")
        self._log(f"  Domain target: {self.domain.get()}", "purp")
        self._log("━" * 60, "dim")

        for i, q in enumerate(queries, 1):
            if self._stop_flag:
                self._log("⏹ Dihentikan oleh pengguna.", "pink")
                break

            self._log(f"[{i}/{len(queries)}] {q}", "yell")
            self._status(f"Scanning {i}/{len(queries)}: {q[:40]}...")

            data, err = self._search(q)
            if err:
                self._log(f"  ✗ Error: {err}", "pink")
                continue

            found = self._parse_results(data, q)
            if not found:
                self._log(f"  → Tidak ada hasil", "dim")
            else:
                self._log(f"  ✓ {len(found)} hasil ditemukan", "green")
                for r in found:
                    self.results.append(r)
                    total += 1
                    self.after(0, self._add_tree, r)
                    self._log(f"    ↳ {r.url[:90]}", "oran")

            self.after(0, self.count_var.set, f"Hasil: {len(self.results)}")

            if i < len(queries) and not self._stop_flag:
                delay = self.delay.get()
                if delay > 0:
                    time.sleep(delay)

        self._log("━" * 60, "dim")
        self._log(f"✅ Selesai! Total hasil terkumpul: {total}", "green")
        self._status(f"Selesai — {total} hasil")
        self.running = False

    def _stop(self):
        self._stop_flag = True
        self._status("Menghentikan...")

    # ─── TREE ─────────────────────────────────────────────────────
    def _add_tree(self, r: DorkResult):
        n = len(self.results)
        self.tree.insert("", "end",
                         values=(n, r.title[:55], r.url[:75],
                                 r.dork_used[:45], r.timestamp))

    def _show_detail(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        idx = int(vals[0]) - 1
        if 0 <= idx < len(self.results):
            r = self.results[idx]
            self.detail.delete("1.0", "end")
            self.detail.insert("end",
                f"━━━━━━━━━━ DETAIL HASIL #{idx+1} ━━━━━━━━━━\n\n"
                f"TITLE   : {r.title}\n\n"
                f"URL     : {r.url}\n\n"
                f"DORK    : {r.dork_used}\n\n"
                f"WAKTU   : {r.timestamp}\n\n"
                f"━━━━━━━━━━ SNIPPET ━━━━━━━━━━\n\n"
                f"{r.snippet}\n"
            )

    def _open_url(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(self.tree.item(sel[0], "values")[0]) - 1
        if 0 <= idx < len(self.results):
            webbrowser.open(self.results[idx].url)

    def _open_selected(self):
        self._open_url()

    # ─── EXPORT ───────────────────────────────────────────────────
    def _export_csv(self):
        if not self.results:
            messagebox.showinfo("Export", "Belum ada hasil.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"dork_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["No", "Title", "URL", "Snippet", "Dork", "Waktu"])
            for i, r in enumerate(self.results, 1):
                w.writerow([i, r.title, r.url, r.snippet, r.dork_used, r.timestamp])
        self._log(f"✅ CSV disimpan: {path}", "green")
        messagebox.showinfo("Export", f"Tersimpan:\n{path}")

    def _export_json(self):
        if not self.results:
            messagebox.showinfo("Export", "Belum ada hasil.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"dork_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path:
            return
        data = [{"no": i+1, "title": r.title, "url": r.url,
                  "snippet": r.snippet, "dork": r.dork_used, "time": r.timestamp}
                for i, r in enumerate(self.results)]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self._log(f"✅ JSON disimpan: {path}", "green")
        messagebox.showinfo("Export", f"Tersimpan:\n{path}")

    def _clear(self):
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        self.detail.delete("1.0", "end")
        self.count_var.set("Hasil: 0")
        self.quota_var.set("Quota: -")
        self._status("Dibersihkan")


if __name__ == "__main__":
    app = GoogleDorker()
    app.mainloop()
