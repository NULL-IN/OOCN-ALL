#!/usr/bin/env python3
"""
Anti-Sniffer v5 — GUI (tkinter)
Система виявлення підозрілої мережевої активності
Організація комп. мереж · Нагорний Ілля · РПЗ-24Б
"""
import socket, struct, sys, time, threading, ipaddress, os
from datetime import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# ── Кольори Catppuccin Mocha ──────────────────────────────────
BG      = "#1e1e2e"
SURFACE = "#181825"
SURF2   = "#313244"
BORDER  = "#45475a"
TEXT    = "#cdd6f4"
SUB     = "#a6adc8"
DIM     = "#6c7086"
BLUE    = "#89b4fa"
GREEN   = "#a6e3a1"
RED     = "#f38ba8"
MAUVE   = "#cba6f7"
PEACH   = "#fab387"
TEAL    = "#94e2d5"
YELLOW  = "#f9e2af"
MONO    = ("Consolas", 10)
UI      = ("Segoe UI", 10)
UI_B    = ("Segoe UI", 10, "bold")
UI_S    = ("Segoe UI", 9)

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PgSQL", 8080: "HTTP-Alt",
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def parse_ip(data):
    if len(data) < 20: return None
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ihl = (iph[0] & 0xF) * 4
    return {"ihl": ihl, "protocol": iph[6],
            "src": socket.inet_ntoa(iph[8]), "dst": socket.inet_ntoa(iph[9]),
            "payload": data[ihl:]}

def parse_tcp(data):
    if len(data) < 20: return None
    t = struct.unpack("!HHLLBBHHH", data[:20])
    f = t[5]
    return {"src_port": t[0], "dst_port": t[1],
            "syn": (f>>1)&1, "ack": (f>>4)&1, "fin": f&1, "rst": (f>>2)&1}

def parse_udp(data):
    if len(data) < 8: return None
    u = struct.unpack("!HHHH", data[:8])
    return {"src_port": u[0], "dst_port": u[1]}


class AntiSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Anti-Sniffer v5 — Нагорний Ілля · РПЗ-24Б")
        self.root.geometry("1050x700")
        self.root.configure(bg=BG)
        self.root.minsize(900, 550)

        self.local_ip = get_local_ip()
        self.running = False
        self.total = self.tcp_c = self.udp_c = self.icmp_c = self.alert_c = 0
        self.start_time = None
        self.port_tracker = defaultdict(list)
        self.req_tracker = defaultdict(list)
        self.seen_ips = set()
        self.alerted_scans = set()
        self.alerted_mass = set()
        self.alerts_list = []
        self.whitelist_nets = [
            ipaddress.ip_network(self.local_ip + "/24", strict=False),
            ipaddress.ip_network("127.0.0.0/8", strict=False),
        ]
        self._lock = threading.Lock()
        self._build_ui()

    # ── UI ────────────────────────────────────────────────────
    def _build_ui(self):
        # header
        hdr = tk.Frame(self.root, bg=SURFACE, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡", font=("Segoe UI", 22), bg=SURFACE, fg=BLUE).pack(side="left", padx=(20,8))
        hf = tk.Frame(hdr, bg=SURFACE)
        hf.pack(side="left")
        tk.Label(hf, text="Anti-Sniffer v5", font=("Segoe UI", 16, "bold"), bg=SURFACE, fg=BLUE).pack(anchor="w")
        tk.Label(hf, text="Система виявлення підозрілої мережевої активності", font=UI_S, bg=SURFACE, fg=SUB).pack(anchor="w")

        # notebook
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SURF2, foreground=SUB, padding=[16,8], font=UI_B)
        style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", BLUE)])
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0,10))

        self._build_monitor_tab()
        self._build_alerts_tab()
        self._build_settings_tab()

    def _build_monitor_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text=" 📡 Моніторинг ")

        # control bar
        bar = tk.Frame(tab, bg=SURFACE, pady=8)
        bar.pack(fill="x", padx=10, pady=(10,0))
        tk.Label(bar, text="IP:", font=UI_B, bg=SURFACE, fg=TEXT).pack(side="left", padx=(12,4))
        self.ip_var = tk.StringVar(value=self.local_ip)
        self.ip_entry = tk.Entry(bar, textvariable=self.ip_var, font=MONO, bg=SURF2, fg=TEXT,
                                  insertbackground=TEXT, relief="flat", width=18, bd=0)
        self.ip_entry.pack(side="left", padx=4, ipady=4)

        self.start_btn = tk.Button(bar, text="▶ Старт", font=UI_B, bg=GREEN, fg=SURFACE,
                                    relief="flat", cursor="hand2", command=self._toggle, padx=14, pady=2)
        self.start_btn.pack(side="left", padx=12)

        self.status_lbl = tk.Label(bar, text="● Зупинено", font=UI_S, bg=SURFACE, fg=DIM)
        self.status_lbl.pack(side="left", padx=8)

        # stat cards
        cards = tk.Frame(tab, bg=BG)
        cards.pack(fill="x", padx=10, pady=8)
        self.stat_vars = {}
        for i, (key, label, color) in enumerate([
            ("total", "Пакетів", TEXT), ("tcp", "TCP", TEAL), ("udp", "UDP", GREEN),
            ("icmp", "ICMP", MAUVE), ("ips", "Унік. IP", YELLOW), ("alerts", "Сповіщень", RED)
        ]):
            f = tk.Frame(cards, bg=SURFACE, bd=0, highlightthickness=1, highlightbackground=BORDER)
            f.pack(side="left", fill="both", expand=True, padx=3)
            v = tk.StringVar(value="0")
            self.stat_vars[key] = v
            tk.Label(f, textvariable=v, font=("Segoe UI", 18, "bold"), bg=SURFACE, fg=color).pack(pady=(8,0))
            tk.Label(f, text=label, font=UI_S, bg=SURFACE, fg=SUB).pack(pady=(0,8))

        # traffic log
        tf = tk.Frame(tab, bg=BG)
        tf.pack(fill="both", expand=True, padx=10, pady=(0,10))
        tk.Label(tf, text="Трафік у реальному часі", font=UI_B, bg=BG, fg=BLUE).pack(anchor="w", pady=(0,4))
        self.traffic_txt = scrolledtext.ScrolledText(tf, font=MONO, bg="#0c0c0c", fg="#ccc",
                                                      relief="flat", wrap="none", height=15, state="disabled")
        self.traffic_txt.pack(fill="both", expand=True)
        self.traffic_txt.tag_config("tcp_in", foreground=TEAL)
        self.traffic_txt.tag_config("tcp_out", foreground=GREEN)
        self.traffic_txt.tag_config("udp", foreground=PEACH)
        self.traffic_txt.tag_config("icmp", foreground=MAUVE)
        self.traffic_txt.tag_config("dim", foreground=DIM)

    def _build_alerts_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text=" ⚠ Сповіщення ")

        af = tk.Frame(tab, bg=BG)
        af.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(af, text="Журнал сповіщень", font=UI_B, bg=BG, fg=RED).pack(anchor="w", pady=(0,4))
        self.alerts_txt = scrolledtext.ScrolledText(af, font=MONO, bg="#0c0c0c", fg="#ccc",
                                                     relief="flat", wrap="word", state="disabled")
        self.alerts_txt.pack(fill="both", expand=True)
        self.alerts_txt.tag_config("crit", foreground=RED)
        self.alerts_txt.tag_config("warn", foreground=YELLOW)
        self.alerts_txt.tag_config("info", foreground=BLUE)
        self.alerts_txt.tag_config("dim", foreground=DIM)

        bf = tk.Frame(af, bg=BG)
        bf.pack(fill="x", pady=(6,0))
        tk.Button(bf, text="💾 Зберегти лог", font=UI_S, bg=SURF2, fg=TEXT, relief="flat",
                  cursor="hand2", command=self._save_log, padx=10).pack(side="left")
        tk.Button(bf, text="🗑 Очистити", font=UI_S, bg=SURF2, fg=TEXT, relief="flat",
                  cursor="hand2", command=self._clear_alerts, padx=10).pack(side="left", padx=8)

    def _build_settings_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text=" ⚙ Налаштування ")
        sf = tk.Frame(tab, bg=SURFACE, bd=0, highlightthickness=1, highlightbackground=BORDER)
        sf.pack(fill="x", padx=20, pady=20)

        settings = [
            ("Поріг порт-скану (портів):", "ps_thr", "10"),
            ("Вікно порт-скану (сек):", "ps_win", "5"),
            ("Поріг масових запитів (пакетів):", "mr_thr", "50"),
            ("Вікно масових запитів (сек):", "mr_win", "3"),
        ]
        self.cfg_vars = {}
        for i, (label, key, default) in enumerate(settings):
            tk.Label(sf, text=label, font=UI, bg=SURFACE, fg=TEXT).grid(row=i, column=0, sticky="w", padx=(16,8), pady=6)
            v = tk.StringVar(value=default)
            self.cfg_vars[key] = v
            tk.Entry(sf, textvariable=v, font=MONO, bg=SURF2, fg=TEXT, insertbackground=TEXT,
                     relief="flat", width=8, bd=0).grid(row=i, column=1, padx=(0,16), pady=6, ipady=3)

        # whitelist
        wf = tk.Frame(tab, bg=SURFACE, bd=0, highlightthickness=1, highlightbackground=BORDER)
        wf.pack(fill="x", padx=20, pady=(0,20))
        tk.Label(wf, text="Білий список (CIDR, через кому):", font=UI_B, bg=SURFACE, fg=BLUE).pack(anchor="w", padx=16, pady=(12,4))
        self.wl_var = tk.StringVar(value=f"{self.local_ip}/24, 127.0.0.0/8")
        tk.Entry(wf, textvariable=self.wl_var, font=MONO, bg=SURF2, fg=TEXT, insertbackground=TEXT,
                 relief="flat", bd=0).pack(fill="x", padx=16, pady=(0,12), ipady=4)

    # ── Логіка ────────────────────────────────────────────────
    def _toggle(self):
        if self.running:
            self.running = False
            self.start_btn.config(text="▶ Старт", bg=GREEN)
            self.status_lbl.config(text="● Зупинено", fg=DIM)
        else:
            self.local_ip = self.ip_var.get().strip()
            self._parse_whitelist()
            self.running = True
            self.start_btn.config(text="■ Стоп", bg=RED)
            self.status_lbl.config(text="● Моніторинг...", fg=GREEN)
            self.start_time = time.time()
            threading.Thread(target=self._capture, daemon=True).start()
            threading.Thread(target=self._update_stats_loop, daemon=True).start()

    def _parse_whitelist(self):
        self.whitelist_nets = []
        for part in self.wl_var.get().split(","):
            part = part.strip()
            if part:
                try: self.whitelist_nets.append(ipaddress.ip_network(part, strict=False))
                except: pass

    def is_wl(self, ip):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in self.whitelist_nets)
        except: return False

    def _add_alert(self, level, msg, src="", details=""):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.alert_c += 1
            self.alerts_list.append({"t": ts, "l": level, "m": msg, "s": src, "d": details})
        tag = "crit" if level == "CRIT" else ("warn" if level == "WARN" else "info")
        icon = "‼ КРИТИЧНО" if level == "CRIT" else ("⚠ УВАГА" if level == "WARN" else "ℹ INFO")
        self._append_alerts(f"[{ts}] [{icon}] {msg}\n", tag)
        if src: self._append_alerts(f"  IP: {src}\n", "dim")
        if details: self._append_alerts(f"  {details}\n\n", "dim")

    def _append_alerts(self, text, tag):
        def do():
            self.alerts_txt.config(state="normal")
            self.alerts_txt.insert("end", text, tag)
            self.alerts_txt.see("end")
            self.alerts_txt.config(state="disabled")
        self.root.after(0, do)

    def _check_scan(self, src, port):
        now = time.time()
        thr = int(self.cfg_vars["ps_thr"].get() or 10)
        win = int(self.cfg_vars["ps_win"].get() or 5)
        self.port_tracker[src].append((port, now))
        self.port_tracker[src] = [(p,t) for p,t in self.port_tracker[src] if now-t < win]
        up = set(p for p,_ in self.port_tracker[src])
        if len(up) >= thr:
            key = (src, int(now // win))
            if key not in self.alerted_scans:
                self.alerted_scans.add(key)
                ps = ", ".join(str(p) for p in sorted(up)[:10])
                self._add_alert("CRIT", "Виявлено сканування портів!", src, f"{len(up)} портів: {ps}")

    def _check_mass(self, src):
        now = time.time()
        thr = int(self.cfg_vars["mr_thr"].get() or 50)
        win = int(self.cfg_vars["mr_win"].get() or 3)
        self.req_tracker[src].append(now)
        self.req_tracker[src] = [t for t in self.req_tracker[src] if now-t < win]
        c = len(self.req_tracker[src])
        if c >= thr:
            key = (src, int(now // win))
            if key not in self.alerted_mass:
                self.alerted_mass.add(key)
                self._add_alert("CRIT", "Масові запити (можливий DDoS)!", src, f"{c} пакетів за {win}с")

    def _check_unknown(self, src):
        if src not in self.seen_ips:
            self.seen_ips.add(src)
            if not self.is_wl(src):
                self._add_alert("WARN", "Підключення з невідомого IP", src, "IP не в білому списку")

    def _add_traffic_line(self, text, tag):
        def do():
            self.traffic_txt.config(state="normal")
            self.traffic_txt.insert("end", text + "\n", tag)
            # limit lines
            lines = int(self.traffic_txt.index("end-1c").split(".")[0])
            if lines > 500:
                self.traffic_txt.delete("1.0", "100.0")
            self.traffic_txt.see("end")
            self.traffic_txt.config(state="disabled")
        self.root.after(0, do)

    def _capture(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(0.5)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Помилка",
                f"Не вдалося відкрити сокет: {e}\nЗапустіть від імені адміністратора."))
            self.running = False
            self.root.after(0, lambda: self.start_btn.config(text="▶ Старт", bg=GREEN))
            self.root.after(0, lambda: self.status_lbl.config(text="● Зупинено", fg=DIM))
            return

        while self.running:
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except: break

            ip = parse_ip(data)
            if not ip: continue
            self.total += 1
            proto = ip["protocol"]
            src, dst = ip["src"], ip["dst"]
            ts = datetime.now().strftime("%H:%M:%S")

            if proto == 6:
                self.tcp_c += 1
                tcp = parse_tcp(ip["payload"])
                if tcp:
                    dp = tcp["dst_port"]; sp = tcp["src_port"]
                    svc = KNOWN_PORTS.get(dp, "")
                    fl = []
                    if tcp["syn"]: fl.append("S")
                    if tcp["ack"]: fl.append("A")
                    if tcp["fin"]: fl.append("F")
                    if tcp["rst"]: fl.append("R")
                    d = "→" if src == self.local_ip else "←"
                    tag = "tcp_out" if src == self.local_ip else "tcp_in"
                    svc_s = f" ({svc})" if svc else ""
                    self._add_traffic_line(
                        f"{ts} {d} TCP  {src}:{sp} → {dst}:{dp}{svc_s} [{','.join(fl)}]", tag)
                    if dst == self.local_ip:
                        self._check_scan(src, dp); self._check_mass(src); self._check_unknown(src)
            elif proto == 17:
                self.udp_c += 1
                udp = parse_udp(ip["payload"])
                if udp:
                    svc = KNOWN_PORTS.get(udp["dst_port"], "")
                    svc_s = f" ({svc})" if svc else ""
                    self._add_traffic_line(
                        f"{ts}   UDP  {src}:{udp['src_port']} → {dst}:{udp['dst_port']}{svc_s}", "udp")
                    if dst == self.local_ip:
                        self._check_mass(src); self._check_unknown(src)
            elif proto == 1:
                self.icmp_c += 1
                self._add_traffic_line(f"{ts}   ICMP {src} → {dst}", "icmp")
                if dst == self.local_ip:
                    self._check_mass(src); self._check_unknown(src)

        try: s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF); s.close()
        except: pass

    def _update_stats_loop(self):
        while self.running:
            self.root.after(0, self._update_cards)
            time.sleep(1)

    def _update_cards(self):
        self.stat_vars["total"].set(str(self.total))
        self.stat_vars["tcp"].set(str(self.tcp_c))
        self.stat_vars["udp"].set(str(self.udp_c))
        self.stat_vars["icmp"].set(str(self.icmp_c))
        self.stat_vars["ips"].set(str(len(self.seen_ips)))
        self.stat_vars["alerts"].set(str(self.alert_c))

    def _save_log(self):
        if not self.alerts_list:
            messagebox.showinfo("Порожньо", "Немає сповіщень для збереження."); return
        path = filedialog.asksaveasfilename(defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt")])
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Anti-Sniffer v5 — Лог сповіщень\n# {datetime.now()}\n\n")
            for a in self.alerts_list:
                f.write(f"[{a['t']}] [{a['l']}] {a['m']} | {a['s']} | {a['d']}\n")
        messagebox.showinfo("Збережено", f"Лог збережено: {path}")

    def _clear_alerts(self):
        self.alerts_txt.config(state="normal"); self.alerts_txt.delete("1.0", "end")
        self.alerts_txt.config(state="disabled")
        self.alerts_list.clear(); self.alert_c = 0


if __name__ == "__main__":
    if sys.platform == "win32": os.system("")
    root = tk.Tk()
    app = AntiSnifferGUI(root)
    root.mainloop()
