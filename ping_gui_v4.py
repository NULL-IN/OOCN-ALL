"""
ping_gui.py — графічна утиліта v4
містить: одиночний ping + сканування мережі + збереження результатів
         + аналіз живого трафіку (Wireshark-style, через scapy)

для вкладки «Аналіз трафіку» потрібно:
  pip install scapy
  npcap.com (Windows драйвер)
  запускати від імені Адміністратора
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import re
import threading
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Аналіз трафіку (Raw Sockets) ──────────────────────────────────────────
# Використовуємо вбудовані "сирі сокети" Windows (без сторонніх npcap/scapy)
import socket
import struct
import os


SYSTEM = platform.system().lower()

# ── кольори (catppuccin mocha) ─────────────────────────────────────────────
CLR = {
    "bg":      "#1E1E2E",
    "surface": "#181825",
    "overlay": "#313244",
    "text":    "#CDD6F4",
    "subtext": "#6C7086",
    "blue":    "#89B4FA",
    "green":   "#A6E3A1",
    "red":     "#F38BA8",
    "yellow":  "#F9E2AF",
    "mauve":   "#CBA6F7",
    "teal":    "#94E2D5",
    "peach":   "#FAB387",
    "sky":     "#89DCEB",
}

# кольори рядків Treeview для аналізатора
ROW_BG = {
    "tcp":   "#1e3a28",
    "http":  "#3a3a1e",
    "https": "#3a341e",
    "udp":   "#1e2a3a",
    "dns":   "#2e1e3a",
    "icmp":  "#1e3a3a",
    "ssh":   "#3a2e1e",
    "other": "#1e1e2e",
}
ROW_FG = {
    "tcp":   "#A6E3A1",
    "http":  "#F9E2AF",
    "https": "#FAB387",
    "udp":   "#89B4FA",
    "dns":   "#CBA6F7",
    "icmp":  "#94E2D5",
    "ssh":   "#FAB387",
    "other": "#6C7086",
}

MAX_HOSTS = 2048


# ══════════════════════════════════════════════════════════════════════════════
#  утиліти ping (без змін з v3)
# ══════════════════════════════════════════════════════════════════════════════

def parse_reply_line(line):
    ll = line.lower()
    if SYSTEM == "windows":
        if "request timed out" in ll:
            return None, "Request timed out."
        if "destination host unreachable" in ll:
            return None, "Destination host unreachable."
        m = re.search(r"time[=<](\d+)ms", ll)
        if m:
            t = int(m.group(1))
            return t, f"time={t}ms" if t > 0 else "time<1ms"
    else:
        if "100% packet loss" in ll or "unreachable" in ll:
            return None, line.strip()
        if "timed out" in ll:
            return None, "Request timed out."
        m = re.search(r"time[=<]([\d.]+)\s*ms", ll)
        if m:
            t = round(float(m.group(1)))
            return t, f"time={t}ms" if t > 0 else "time<1ms"
        m = re.search(r"icmp_seq=\d+.*time[=<]([\d.]+)\s*ms", ll)
        if m:
            t = round(float(m.group(1)))
            return t, f"time={t}ms" if t > 0 else "time<1ms"
    return None, None


def ping_once_ms(ip_str):
    if SYSTEM == "windows":
        cmd = ["ping", "-n", "1", "-w", "800", ip_str]
        enc = "ascii"
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        enc = "utf-8"
    try:
        r = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=4, encoding=enc, errors="replace"
        )
        if r.returncode != 0:
            return -1
        out = r.stdout.lower()
        m = re.search(r"time[=<]([\d.]+)\s*ms", out)
        if m:
            return round(float(m.group(1)))
        if "time<1ms" in out or "time <1ms" in out:
            return 0
        return 0
    except Exception:
        return -1


def build_host_list(network_str, use_mask, mask_str):
    if use_mask and mask_str:
        base_ip = network_str.split("/")[0].strip()
        net = ipaddress.IPv4Network(f"{base_ip}/{mask_str}", strict=False)
        total = net.num_addresses - 2
        if total > MAX_HOSTS:
            raise ValueError(f"Мережа містить {total} хостів — максимум {MAX_HOSTS}.")
        return list(net.hosts()), str(net), str(net.netmask)
    if "/" in network_str:
        net = ipaddress.IPv4Network(network_str, strict=False)
        total = net.num_addresses - 2
        if total > MAX_HOSTS:
            raise ValueError(f"Мережа містить {total} хостів — максимум {MAX_HOSTS}.")
        return list(net.hosts()), str(net), str(net.netmask)
    if "-" in network_str:
        parts = network_str.split("-")
        start = ipaddress.IPv4Address(parts[0].strip())
        end   = ipaddress.IPv4Address(parts[1].strip())
        total = int(end) - int(start) + 1
        if total > MAX_HOSTS:
            raise ValueError(f"Діапазон містить {total} хостів — максимум {MAX_HOSTS}.")
        hosts, cur = [], start
        while cur <= end:
            hosts.append(cur)
            cur += 1
        return hosts, f"{start} – {end}", "—"
    net = ipaddress.IPv4Network(f"{network_str}/24", strict=False)
    return list(net.hosts()), str(net), str(net.netmask)


def make_readonly(widget):
    def _block(e):
        if e.state & 0x4 and e.keysym.lower() in ('c', 'a', 'x'):
            return None
        if e.keysym in ('Up', 'Down', 'Left', 'Right', 'Home', 'End',
                        'Prior', 'Next', 'Shift_L', 'Shift_R',
                        'Control_L', 'Control_R'):
            return None
        return "break"
    widget.bind("<Key>", _block)
    widget.bind("<<Paste>>", lambda e: "break")
    widget.config(cursor="arrow")


# ══════════════════════════════════════════════════════════════════════════════
#  вкладка 1 — одиночний ping (без змін з v3)
# ══════════════════════════════════════════════════════════════════════════════

def run_single_ping(host, count, output, stats_frame, btn, root):
    def append(text, tag=None):
        output.insert(tk.END, (text + "\n"), tag)
        output.see(tk.END)
        root.update_idletasks()

    output.delete("1.0", tk.END)
    for w in stats_frame.winfo_children():
        w.destroy()

    append(f"Pinging {host} with 32 bytes of data:\n", "header")

    if SYSTEM == "windows":
        cmd = f"chcp 437 >nul & ping -n {count} {host}"
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="ascii", errors="replace", shell=True
        )
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )

    times, received, stats_started = [], 0, False

    for raw in iter(proc.stdout.readline, ""):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        t, display = parse_reply_line(line)
        if t is not None:
            received += 1
            times.append(t)
            append(f"Reply from {host}: bytes=32 {display} TTL=128", "reply")
        elif display:
            if "statistics" in line.lower() or "статистика" in line.lower():
                stats_started = True
            if not stats_started:
                tag = "timeout" if ("timeout" in line.lower() or "loss" in line.lower()) else None
                append(line, tag)
    proc.wait()

    lost     = count - received
    loss_pct = round((lost / count) * 100) if count > 0 else 0
    append(f"\nPing statistics for {host}:", "header")
    append(f"    Packets: Sent = {count}, Received = {received}, Lost = {lost} ({loss_pct}% loss)", "header")

    if times:
        mn, mx, av = min(times), max(times), round(sum(times) / len(times))
        append("Approximate round trip times in milli-seconds:")
        append(f"    Minimum = {mn}ms, Maximum = {mx}ms, Average = {av}ms")
        cards = [
            ("Надіслано", count,       CLR["green"]),
            ("Отримано",  received,    CLR["blue"]),
            ("Втрачено",  lost,        CLR["red"]),
            ("Мін. час",  f"{mn} мс",  CLR["mauve"]),
            ("Макс. час", f"{mx} мс",  CLR["peach"]),
            ("Сер. час",  f"{av} мс",  CLR["teal"]),
        ]
        for i, (lbl, val, col) in enumerate(cards):
            card = tk.Frame(stats_frame, bg=col, padx=10, pady=6)
            card.grid(row=0, column=i, padx=4, pady=4, sticky="ew")
            stats_frame.columnconfigure(i, weight=1)
            tk.Label(card, text=str(val), font=("Consolas", 16, "bold"),
                     fg="white", bg=col).pack()
            tk.Label(card, text=lbl, font=("Consolas", 9),
                     fg="white", bg=col).pack()
    btn.config(state="normal")


def tab_ping(notebook, root):
    frame = tk.Frame(notebook, bg=CLR["bg"])
    inp = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=10)
    inp.pack(fill="x")

    tk.Label(inp, text="Хост / IP:", font=("Consolas", 10),
             fg=CLR["text"], bg=CLR["bg"]).grid(row=0, column=0, sticky="w", padx=(0, 8))
    host_var = tk.StringVar(value="8.8.8.8")
    tk.Entry(inp, textvariable=host_var, font=("Consolas", 11),
             bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
             relief="flat", width=26).grid(row=0, column=1, padx=(0, 16), ipady=4)

    tk.Label(inp, text="Кількість:", font=("Consolas", 10),
             fg=CLR["text"], bg=CLR["bg"]).grid(row=0, column=2, sticky="w", padx=(0, 8))
    count_var = tk.StringVar(value="4")
    ttk.Spinbox(inp, from_=1, to=100, textvariable=count_var,
                font=("Consolas", 11), width=6).grid(row=0, column=3, padx=(0, 16), ipady=4)

    btn = tk.Button(inp, text="  Ping  ", font=("Consolas", 11, "bold"),
                    bg=CLR["blue"], fg=CLR["surface"], activebackground=CLR["teal"],
                    relief="flat", padx=10, pady=4, cursor="hand2")
    btn.grid(row=0, column=4)

    term = tk.Frame(frame, bg=CLR["bg"], padx=16)
    term.pack(fill="both", expand=True)
    output = scrolledtext.ScrolledText(
        term, font=("Consolas", 10), bg="#11111B", fg=CLR["text"],
        insertbackground=CLR["text"], relief="flat", wrap="word"
    )
    output.pack(fill="both", expand=True, pady=(0, 6))
    output.tag_config("header",  foreground=CLR["blue"])
    output.tag_config("reply",   foreground=CLR["green"])
    output.tag_config("timeout", foreground=CLR["red"])
    output.tag_config("error",   foreground=CLR["red"])
    make_readonly(output)

    stats_frame = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=6)
    stats_frame.pack(fill="x")

    def do_ping():
        host = host_var.get().strip()
        if not host:
            return
        try:
            count = max(1, min(int(count_var.get()), 100))
        except ValueError:
            count = 4
        btn.config(state="disabled")
        threading.Thread(
            target=run_single_ping,
            args=(host, count, output, stats_frame, btn, root),
            daemon=True
        ).start()

    btn.config(command=do_ping)
    frame.bind_all("<Return>", lambda e: do_ping())
    return frame


# ══════════════════════════════════════════════════════════════════════════════
#  вкладка 2 — сканування мережі (без змін з v3)
# ══════════════════════════════════════════════════════════════════════════════

def tab_scan(notebook, root):
    frame = tk.Frame(notebook, bg=CLR["bg"])

    row1 = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=8)
    row1.pack(fill="x")
    tk.Label(row1, text="Мережа / CIDR / діапазон:", font=("Consolas", 10),
             fg=CLR["text"], bg=CLR["bg"]).grid(row=0, column=0, sticky="w", padx=(0, 8))
    net_var = tk.StringVar(value="192.168.1.0/24")
    tk.Entry(row1, textvariable=net_var, font=("Consolas", 11),
             bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
             relief="flat", width=30).grid(row=0, column=1, ipady=4, padx=(0, 20))

    row2 = tk.Frame(frame, bg=CLR["bg"], padx=16)
    row2.pack(fill="x")
    use_mask_var = tk.BooleanVar(value=False)
    tk.Checkbutton(row2, text="Вказати маску окремо", variable=use_mask_var,
                   font=("Consolas", 10), fg=CLR["text"], bg=CLR["bg"],
                   activebackground=CLR["bg"], activeforeground=CLR["blue"],
                   selectcolor=CLR["overlay"], cursor="hand2"
                   ).grid(row=0, column=0, sticky="w")
    mask_var = tk.StringVar(value="255.255.255.0")
    mask_entry = tk.Entry(row2, textvariable=mask_var, font=("Consolas", 11),
                          bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
                          relief="flat", width=18, state="disabled")
    mask_entry.grid(row=0, column=1, ipady=4, padx=(12, 0))
    use_mask_var.trace_add("write",
        lambda *_: mask_entry.config(state="normal" if use_mask_var.get() else "disabled"))

    row3 = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=8)
    row3.pack(fill="x")
    btn_scan = tk.Button(row3, text="  Сканувати  ", font=("Consolas", 11, "bold"),
                         bg=CLR["mauve"], fg=CLR["surface"], activebackground=CLR["blue"],
                         relief="flat", padx=10, pady=4, cursor="hand2")
    btn_scan.grid(row=0, column=0, padx=(0, 12))
    progress_var = tk.DoubleVar(value=0)
    progress_lbl = tk.Label(row3, text="", font=("Consolas", 9),
                            fg=CLR["subtext"], bg=CLR["bg"])
    progress_lbl.grid(row=0, column=1, sticky="w")
    ttk.Progressbar(row3, variable=progress_var, maximum=100, length=300
                    ).grid(row=0, column=2, padx=(10, 0))

    term = tk.Frame(frame, bg=CLR["bg"], padx=16)
    term.pack(fill="both", expand=True)
    output = scrolledtext.ScrolledText(
        term, font=("Consolas", 10), bg="#11111B", fg=CLR["text"],
        insertbackground=CLR["text"], relief="flat", state="disabled", wrap="none"
    )
    output.pack(fill="both", expand=True, pady=(4, 6))
    output.tag_config("up",      foreground=CLR["green"])
    output.tag_config("down",    foreground=CLR["subtext"])
    output.tag_config("header",  foreground=CLR["blue"])
    output.tag_config("summary", foreground=CLR["yellow"])
    output.tag_config("error",   foreground=CLR["red"])

    summary_frame = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=6)
    summary_frame.pack(fill="x")

    scan_results = {"alive": [], "dead": []}

    def append(text, tag=None):
        output.config(state="normal")
        output.insert(tk.END, text + "\n", tag)
        output.see(tk.END)
        output.config(state="disabled")
        root.update_idletasks()

    def do_scan():
        net_str  = net_var.get().strip()
        use_mask = use_mask_var.get()
        mask_str = mask_var.get().strip() if use_mask else None
        if not net_str:
            messagebox.showwarning("Увага", "Введіть адресу мережі або діапазон IP")
            return
        output.config(state="normal")
        output.delete("1.0", tk.END)
        output.config(state="disabled")
        for w in summary_frame.winfo_children():
            w.destroy()
        progress_var.set(0)
        progress_lbl.config(text="")
        scan_results["alive"] = []
        scan_results["dead"]  = []
        try:
            hosts, net_label, netmask = build_host_list(net_str, use_mask, mask_str)
        except ValueError as e:
            append(f"Помилка адреси: {e}", "error")
            return
        if not hosts:
            append("Не знайдено хостів у вказаному діапазоні.", "error")
            return
        btn_scan.config(state="disabled")

        def worker():
            append(f"Сканування: {net_label}  (маска: {netmask})", "header")
            append(f"Хостів для перевірки: {len(hosts)}", "header")
            append(f"{'IP-адреса':<22} {'Статус':<10} Затримка", "header")
            append("─" * 46, "header")
            alive, dead = [], []
            done_count = [0]
            lock = threading.Lock()

            def check(host_addr):
                ip_str = str(host_addr)
                ms = ping_once_ms(ip_str)
                with lock:
                    done_count[0] += 1
                    progress_var.set(done_count[0] / len(hosts) * 100)
                    progress_lbl.config(text=f"{done_count[0]}/{len(hosts)}")
                    if ms >= 0:
                        ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                        alive.append((ip_str, ms))
                        append(f"{ip_str:<22} {'Up':<10} {ms_str}", "up")
                    else:
                        dead.append(ip_str)
                        append(f"{ip_str:<22} {'Down':<10} —", "down")

            with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as ex:
                for f in as_completed({ex.submit(check, h): h for h in hosts}):
                    pass

            scan_results["alive"] = alive
            scan_results["dead"]  = dead

            append("─" * 46, "summary")
            append(f"\n{'Активних хостів':<22} {len(alive)}", "summary")
            append(f"{'Неактивних хостів':<22} {len(dead)}", "summary")
            append(f"{'Всього перевірено':<22} {len(hosts)}", "summary")

            if alive:
                append("\nАктивні хости (відсортовано):", "summary")
                for ip, ms in sorted(alive, key=lambda x: ipaddress.IPv4Address(x[0])):
                    ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                    append(f"  ✔  {ip:<20} {ms_str}", "up")

            for i, (lbl, val, col) in enumerate([
                ("Перевірено",  len(hosts), CLR["blue"]),
                ("Активних",    len(alive), CLR["green"]),
                ("Неактивних",  len(dead),  CLR["red"]),
            ]):
                card = tk.Frame(summary_frame, bg=col, padx=14, pady=6)
                card.grid(row=0, column=i, padx=6, pady=4, sticky="ew")
                summary_frame.columnconfigure(i, weight=1)
                tk.Label(card, text=str(val), font=("Consolas", 18, "bold"),
                         fg="white", bg=col).pack()
                tk.Label(card, text=lbl, font=("Consolas", 9),
                         fg="white", bg=col).pack()

            progress_var.set(100)
            progress_lbl.config(text="Готово")
            btn_scan.config(state="normal")

        threading.Thread(target=worker, daemon=True).start()

    btn_scan.config(command=do_scan)
    return frame, scan_results


# ══════════════════════════════════════════════════════════════════════════════
#  вкладка 3 — збереження результатів (без змін з v3)
# ══════════════════════════════════════════════════════════════════════════════

def tab_save(notebook, root, scan_results):
    frame = tk.Frame(notebook, bg=CLR["bg"])

    hdr = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=12)
    hdr.pack(fill="x")
    tk.Label(hdr, text="Збереження та сортування результатів",
             font=("Consolas", 12, "bold"), fg=CLR["blue"], bg=CLR["bg"]).pack(anchor="w")
    tk.Label(hdr, text="Результати останнього сканування розподіляються на активні та неактивні хости",
             font=("Consolas", 9), fg=CLR["subtext"], bg=CLR["bg"]).pack(anchor="w")

    files_frame = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=4)
    files_frame.pack(fill="x")

    tk.Label(files_frame, text="Файл активних хостів:",
             font=("Consolas", 10), fg=CLR["green"], bg=CLR["bg"]
             ).grid(row=0, column=0, sticky="w", pady=4, padx=(0, 10))
    active_path_var = tk.StringVar(value="active_hosts.txt")
    tk.Entry(files_frame, textvariable=active_path_var, font=("Consolas", 10),
             bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
             relief="flat", width=36).grid(row=0, column=1, ipady=4, padx=(0, 8))
    tk.Button(files_frame, text="…", font=("Consolas", 10),
              bg=CLR["overlay"], fg=CLR["text"], relief="flat", cursor="hand2",
              command=lambda: active_path_var.set(
                  filedialog.asksaveasfilename(defaultextension=".txt",
                      filetypes=[("Text files", "*.txt")],
                      initialfile="active_hosts.txt") or active_path_var.get()
              )).grid(row=0, column=2)

    tk.Label(files_frame, text="Файл неактивних хостів:",
             font=("Consolas", 10), fg=CLR["red"], bg=CLR["bg"]
             ).grid(row=1, column=0, sticky="w", pady=4, padx=(0, 10))
    inactive_path_var = tk.StringVar(value="inactive_hosts.txt")
    tk.Entry(files_frame, textvariable=inactive_path_var, font=("Consolas", 10),
             bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
             relief="flat", width=36).grid(row=1, column=1, ipady=4, padx=(0, 8))
    tk.Button(files_frame, text="…", font=("Consolas", 10),
              bg=CLR["overlay"], fg=CLR["text"], relief="flat", cursor="hand2",
              command=lambda: inactive_path_var.set(
                  filedialog.asksaveasfilename(defaultextension=".txt",
                      filetypes=[("Text files", "*.txt")],
                      initialfile="inactive_hosts.txt") or inactive_path_var.get()
              )).grid(row=1, column=2)

    btn_row = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=10)
    btn_row.pack(fill="x")
    btn_save = tk.Button(btn_row, text="  Зберегти результати  ",
                         font=("Consolas", 11, "bold"),
                         bg=CLR["teal"], fg=CLR["surface"],
                         activebackground=CLR["green"],
                         relief="flat", padx=12, pady=5, cursor="hand2")
    btn_save.pack(side="left")
    status_lbl = tk.Label(btn_row, text="",
                          font=("Consolas", 10), fg=CLR["yellow"], bg=CLR["bg"])
    status_lbl.pack(side="left", padx=16)

    preview_frame = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=4)
    preview_frame.pack(fill="both", expand=True)
    tk.Label(preview_frame, text="Попередній перегляд результатів:",
             font=("Consolas", 10, "bold"), fg=CLR["text"], bg=CLR["bg"]
             ).pack(anchor="w", pady=(0, 4))

    pv = tk.Frame(preview_frame, bg=CLR["bg"])
    pv.pack(fill="both", expand=True)
    pv.columnconfigure(0, weight=1)
    pv.columnconfigure(1, weight=1)

    tk.Label(pv, text="✔ Активні хости",
             font=("Consolas", 9, "bold"), fg=CLR["green"], bg=CLR["bg"]
             ).grid(row=0, column=0, sticky="w", padx=(0, 8))
    active_box = scrolledtext.ScrolledText(pv, font=("Consolas", 9), bg="#11111B", fg=CLR["green"],
                                           relief="flat", width=30, height=14)
    active_box.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
    make_readonly(active_box)

    tk.Label(pv, text="✘ Неактивні хости",
             font=("Consolas", 9, "bold"), fg=CLR["red"], bg=CLR["bg"]
             ).grid(row=0, column=1, sticky="w")
    inactive_box = scrolledtext.ScrolledText(pv, font=("Consolas", 9), bg="#11111B", fg=CLR["red"],
                                             relief="flat", width=30, height=14)
    inactive_box.grid(row=1, column=1, sticky="nsew")
    make_readonly(inactive_box)
    pv.rowconfigure(1, weight=1)

    def refresh_preview(*_):
        active_box.config(state="normal")
        inactive_box.config(state="normal")
        active_box.delete("1.0", tk.END)
        inactive_box.delete("1.0", tk.END)
        alive = scan_results.get("alive", [])
        dead  = scan_results.get("dead",  [])
        if alive:
            for ip, ms in sorted(alive, key=lambda x: ipaddress.IPv4Address(x[0])):
                ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                active_box.insert(tk.END, f"{ip:<20} {ms_str}\n")
        else:
            active_box.insert(tk.END, "(немає даних — спочатку виконайте сканування)\n")
        if dead:
            for ip in sorted(dead, key=lambda x: ipaddress.IPv4Address(x)):
                inactive_box.insert(tk.END, f"{ip}\n")
        else:
            inactive_box.insert(tk.END, "(немає даних)\n")
        active_box.config(state="disabled")
        inactive_box.config(state="disabled")

    def do_save():
        alive = scan_results.get("alive", [])
        dead  = scan_results.get("dead",  [])
        if not alive and not dead:
            messagebox.showwarning("Увага", "Немає даних.\nСпочатку виконайте сканування.")
            return
        active_file   = active_path_var.get().strip() or "active_hosts.txt"
        inactive_file = inactive_path_var.get().strip() or "inactive_hosts.txt"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(active_file, "w", encoding="utf-8") as f:
                f.write(f"# активні хости — {timestamp}\n# всього: {len(alive)}\n\n")
                for ip, ms in sorted(alive, key=lambda x: ipaddress.IPv4Address(x[0])):
                    ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                    f.write(f"{ip:<20} {ms_str}\n")
            with open(inactive_file, "w", encoding="utf-8") as f:
                f.write(f"# неактивні хости — {timestamp}\n# всього: {len(dead)}\n\n")
                for ip in sorted(dead, key=lambda x: ipaddress.IPv4Address(x)):
                    f.write(f"{ip}\n")
            status_lbl.config(
                text=f"✔ Збережено: {len(alive)} активних, {len(dead)} неактивних",
                fg=CLR["green"])
            refresh_preview()
        except Exception as e:
            status_lbl.config(text=f"✘ Помилка: {e}", fg=CLR["red"])

    btn_save.config(command=do_save)
    tk.Button(btn_row, text="  Оновити перегляд  ",
              font=("Consolas", 10), bg=CLR["overlay"], fg=CLR["text"],
              relief="flat", padx=8, pady=4, cursor="hand2",
              command=refresh_preview).pack(side="left", padx=8)
    return frame


# ══════════════════════════════════════════════════════════════════════════════
#  НОВА вкладка 4 — аналіз живого трафіку (Wireshark-style)
# ══════════════════════════════════════════════════════════════════════════════

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def _parse_raw_packet(data):
    try:
        ip_header = data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        proto_name = str(protocol)
        info = ""
        length = len(data)
        
        if protocol == 1:
            proto_name = "icmp"
            info = "ICMP Message"
        elif protocol == 6:
            tcp_header = data[iph_length:iph_length+20]
            if len(tcp_header) == 20:
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dest_port = tcph[1]
                if src_port == 80 or dest_port == 80: proto_name = "http"
                elif src_port == 443 or dest_port == 443: proto_name = "https"
                elif src_port == 22 or dest_port == 22: proto_name = "ssh"
                else: proto_name = "tcp"
                info = f"{src_port} -> {dest_port}"
        elif protocol == 17:
            udp_header = data[iph_length:iph_length+8]
            if len(udp_header) == 8:
                udph = struct.unpack('!HHHH', udp_header)
                src_port = udph[0]
                dest_port = udph[1]
                if src_port == 53 or dest_port == 53: proto_name = "dns"
                else: proto_name = "udp"
                info = f"{src_port} -> {dest_port}"
        else:
            proto_name = "other"

        return {
            "time":  datetime.now().strftime("%H:%M:%S.%f")[:12],
            "src":   s_addr,
            "dst":   d_addr,
            "proto": proto_name,
            "len":   length,
            "info":  info,
        }
    except Exception:
        return None


def tab_traffic(notebook, root):
    """вкладка аналізу живого трафіку — Wireshark-style"""
    frame = tk.Frame(notebook, bg=CLR["bg"])

    # ── стан захоплення ───────────────────────────────────────────────────
    state = {
        "capturing":  False,
        "stop_event": threading.Event(),
        "packets":    [],
        "counter":    0,
        "lock":       threading.Lock(),
    }

    # ── верхня панель управління ──────────────────────────────────────────
    ctrl = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=8)
    ctrl.pack(fill="x")

    # кнопки
    btn_start = tk.Button(ctrl, text="▶  Почати захоплення",
                          font=("Consolas", 10, "bold"),
                          bg=CLR["green"], fg=CLR["surface"],
                          activebackground=CLR["teal"],
                          relief="flat", padx=12, pady=4, cursor="hand2")
    btn_start.grid(row=0, column=0, padx=(0, 8))

    btn_stop = tk.Button(ctrl, text="■  Зупинити",
                         font=("Consolas", 10, "bold"),
                         bg=CLR["overlay"], fg=CLR["subtext"],
                         relief="flat", padx=10, pady=4, cursor="hand2",
                         state="disabled")
    btn_stop.grid(row=0, column=1, padx=(0, 8))

    btn_clear = tk.Button(ctrl, text="🗑 Очистити",
                          font=("Consolas", 10), bg=CLR["overlay"], fg=CLR["text"],
                          relief="flat", padx=8, pady=4, cursor="hand2")
    btn_clear.grid(row=0, column=2, padx=(0, 8))

    btn_save = tk.Button(ctrl, text="💾 Зберегти",
                         font=("Consolas", 10), bg=CLR["overlay"], fg=CLR["text"],
                         relief="flat", padx=8, pady=4, cursor="hand2")
    btn_save.grid(row=0, column=3, padx=(0, 20))

    # фільтр IP
    tk.Label(ctrl, text="Фільтр IP:", font=("Consolas", 9),
             fg=CLR["subtext"], bg=CLR["bg"]).grid(row=0, column=4, padx=(0, 6))
    ip_filter_var = tk.StringVar(value="")
    tk.Entry(ctrl, textvariable=ip_filter_var, font=("Consolas", 10),
             bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
             relief="flat", width=18).grid(row=0, column=5, ipady=3, padx=(0, 16))

    status_var = tk.StringVar(value="  Очікування...")
    tk.Label(ctrl, textvariable=status_var, font=("Consolas", 9),
             fg=CLR["subtext"], bg=CLR["bg"]).grid(row=0, column=99, sticky="e", padx=(10, 0))
    ctrl.columnconfigure(99, weight=1)

    # ── Treeview з вкладками по протоколах ───────────────────────────────
    tab_nb = ttk.Notebook(frame)
    tab_nb.pack(fill="both", expand=True, padx=10, pady=(4, 0))

    TABS = [
        ("Всі пакети", None),
        ("TCP",        ["tcp"]),
        ("HTTP/S",     ["http", "https"]),
        ("UDP",        ["udp"]),
        ("DNS",        ["dns"]),
        ("ICMP",       ["icmp"]),
        ("SSH",        ["ssh"]),
    ]
    COLUMNS = ("#", "Час", "Джерело", "Призначення", "Протокол", "Довж.", "Інформація")
    COL_W   = (50, 110, 155, 155, 80, 55, 340)

    trees = {}  # tab_name → ttk.Treeview

    style2 = ttk.Style()
    style2.configure("Pkt.Treeview",
                     background="#11111B", fieldbackground="#11111B",
                     foreground=CLR["text"], rowheight=21,
                     font=("Consolas", 9))
    style2.configure("Pkt.Treeview.Heading",
                     background=CLR["overlay"], foreground=CLR["blue"],
                     font=("Consolas", 9, "bold"), relief="flat")
    style2.map("Pkt.Treeview",
               background=[("selected", CLR["blue"])],
               foreground=[("selected", CLR["surface"])])

    for tab_name, _ in TABS:
        tf = tk.Frame(tab_nb, bg=CLR["surface"])
        tab_nb.add(tf, text=f"  {tab_name}  ")
        tree = ttk.Treeview(tf, columns=COLUMNS, show="headings",
                            style="Pkt.Treeview", selectmode="browse")
        for col, w in zip(COLUMNS, COL_W):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w",
                        stretch=(col == "Інформація"))
        for p, bg_ in ROW_BG.items():
            tree.tag_configure(p, background=bg_, foreground=ROW_FG.get(p, CLR["text"]))
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        trees[tab_name] = tree

    # клік по рядку — деталі
    detail_var = tk.StringVar(value="— Оберіть рядок для деталей —")
    det_bar = tk.Frame(frame, bg=CLR["bg"], padx=10, pady=4)
    det_bar.pack(fill="x")
    tk.Label(det_bar, text="Деталі:", font=("Consolas", 9, "bold"),
             fg=CLR["blue"], bg=CLR["bg"]).pack(side="left")
    tk.Label(det_bar, textvariable=detail_var, font=("Consolas", 9),
             fg=CLR["subtext"], bg=CLR["bg"], anchor="w").pack(side="left", fill="x")

    def on_tree_select(event):
        widget = event.widget
        sel = widget.selection()
        if not sel:
            return
        vals = widget.item(sel[0], "values")
        if vals:
            idx = int(vals[0]) - 1
            with state["lock"]:
                if 0 <= idx < len(state["packets"]):
                    p = state["packets"][idx]
                    detail_var.set(
                        f"[{p['proto'].upper()}]  {p['src']}  →  {p['dst']}  |  "
                        f"{p['len']} bytes  |  {p['time']}  |  {p['info']}"
                    )

    for tree in trees.values():
        tree.bind("<<TreeviewSelect>>", on_tree_select)

    # ── статистика ────────────────────────────────────────────────────────
    stat_frame = tk.Frame(frame, bg=CLR["bg"], padx=10, pady=6)
    stat_frame.pack(fill="x")
    stat_labels = {}
    for i, (lbl, key, col) in enumerate([
        ("Всього",  "all",   CLR["blue"]),
        ("TCP",     "tcp",   CLR["green"]),
        ("HTTP/S",  "http",  CLR["yellow"]),
        ("UDP",     "udp",   CLR["blue"]),
        ("DNS",     "dns",   CLR["mauve"]),
        ("ICMP",    "icmp",  CLR["teal"]),
        ("SSH",     "ssh",   CLR["peach"]),
    ]):
        card = tk.Frame(stat_frame, bg=col, padx=10, pady=4)
        card.grid(row=0, column=i, padx=4, sticky="ew")
        stat_frame.columnconfigure(i, weight=1)
        v = tk.Label(card, text="0", font=("Consolas", 13, "bold"),
                     fg="white", bg=col)
        v.pack()
        tk.Label(card, text=lbl, font=("Consolas", 8),
                 fg="white", bg=col).pack()
        stat_labels[key] = v

    # ── внутрішні функції ─────────────────────────────────────────────────

    def _update_stats():
        from collections import Counter
        cnt = Counter(p["proto"] for p in state["packets"])
        stat_labels["all"].config(text=str(len(state["packets"])))
        stat_labels["tcp"].config(text=str(cnt.get("tcp", 0)))
        stat_labels["http"].config(text=str(cnt.get("http", 0) + cnt.get("https", 0)))
        stat_labels["udp"].config(text=str(cnt.get("udp", 0)))
        stat_labels["dns"].config(text=str(cnt.get("dns", 0)))
        stat_labels["icmp"].config(text=str(cnt.get("icmp", 0)))
        stat_labels["ssh"].config(text=str(cnt.get("ssh", 0)))

    def _insert_row(idx, p):
        proto = p["proto"]
        tag   = proto if proto in ROW_BG else "other"
        row   = (idx, p["time"], p["src"], p["dst"], p["proto"].upper(), p["len"], p["info"])

        # вкладка "Всі пакети" — завжди вставляємо
        trees["Всі пакети"].insert("", "end", values=row, tags=(tag,))
        trees["Всі пакети"].see(trees["Всі пакети"].get_children()[-1])

        # вкладки по протоколу — лише якщо збігається
        for tab_name, protos in TABS[1:]:
            if protos and proto in protos:
                trees[tab_name].insert("", "end", values=row, tags=(tag,))
                trees[tab_name].see(trees[tab_name].get_children()[-1])
                break

        _update_stats()
        status_var.set(f"  🔴 Захоплення...  пакетів: {idx}")

    def _on_packet(info):
        if not info:
            return
        ip_f = ip_filter_var.get().strip()
        if ip_f and ip_f not in (info["src"], info["dst"]):
            return
        with state["lock"]:
            state["counter"]  += 1
            idx = state["counter"]
            state["packets"].append(info)
        root.after(0, lambda i=idx, p=info: _insert_row(i, p))

    def _capture_worker(local_ip):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if os.name == 'nt':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while not state["stop_event"].is_set():
                sock.settimeout(1.0)
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                info = _parse_raw_packet(data)
                if info:
                    _on_packet(info)

        except OSError as e:
            if getattr(e, "winerror", 0) == 10013 or "access denied" in str(e).lower() or "доступу" in str(e).lower():
                root.after(0, lambda: messagebox.showerror("Помилка доступу", "Сніфер вимагає запуску від імені АДМІНІСТРАТОРА!"))
            else:
                root.after(0, lambda err=e: messagebox.showerror("Помилка", f"Мережева помилка: {err}"))
        except Exception as e:
            root.after(0, lambda err=e: messagebox.showerror("Помилка", f"Неочікувана помилка: {err}"))
        finally:
            if sock and os.name == 'nt':
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            if sock:
                sock.close()
            root.after(0, _on_done)

    def _on_done():
        state["capturing"] = False
        btn_start.config(state="normal",  bg=CLR["green"],   fg=CLR["surface"])
        btn_stop.config(state="disabled", bg=CLR["overlay"], fg=CLR["subtext"])
        status_var.set(f"  ⏹ Зупинено. Всього пакетів: {state['counter']}")

    def do_start():
        local_ip = _get_local_ip()
        state["capturing"] = True
        state["stop_event"].clear()
        btn_start.config(state="disabled", bg=CLR["overlay"], fg=CLR["subtext"])
        btn_stop.config(state="normal",    bg=CLR["red"],     fg=CLR["surface"])
        status_var.set(f"  🔴 Захоплення... [{local_ip}]")
        threading.Thread(target=_capture_worker, args=(local_ip,), daemon=True).start()

    def do_stop():
        state["stop_event"].set()

    def do_clear():
        state["stop_event"].set()
        with state["lock"]:
            state["packets"].clear()
            state["counter"] = 0
        for tree in trees.values():
            for item in tree.get_children():
                tree.delete(item)
        for lbl in stat_labels.values():
            lbl.config(text="0")
        status_var.set("  Очищено.")

    def do_save_capture():
        pkts = state["packets"][:]
        if not pkts:
            messagebox.showinfo("Немає даних", "Спочатку захопіть трафік.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
            initialfile="capture.txt"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# захоплення трафіку — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# пакетів: {len(pkts)}\n\n")
                f.write(f"{'#':<5} {'Час':<13} {'Джерело':<18} {'Призначення':<18} "
                        f"{'Протокол':<10} {'Довж.':<7} Інформація\n")
                f.write("─" * 88 + "\n")
                for i, p in enumerate(pkts, 1):
                    f.write(f"{i:<5} {p['time']:<13} {p['src']:<18} {p['dst']:<18} "
                            f"{p['proto'].upper():<10} {p['len']:<7} {p['info']}\n")
            messagebox.showinfo("Збережено", f"{path}\nПакетів: {len(pkts)}")
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    btn_start.config(command=do_start)
    btn_stop.config(command=do_stop)
    btn_clear.config(command=do_clear)
    btn_save.config(command=do_save_capture)

    # Запускати від Адміністратора — єдина вимога!
    warn = tk.Label(frame, text="⚠ Для роботи сніфера обов'язково запустіть програму від імені Адміністратора",
                    font=("Consolas", 9, "bold"), fg=CLR["teal"], bg=CLR["bg"])
    warn.pack(pady=4)

    return frame


# ══════════════════════════════════════════════════════════════════════════════
#  головне вікно
# ══════════════════════════════════════════════════════════════════════════════

def build_gui():
    root = tk.Tk()
    root.title("Ping Utility v4 – Cisco Packet Tracer Style")
    root.geometry("1050x680")
    root.minsize(800, 540)
    root.configure(bg=CLR["surface"])

    hdr = tk.Frame(root, bg=CLR["surface"], pady=10)
    hdr.pack(fill="x")
    tk.Label(hdr, text="Ping Utility v4",
             font=("Consolas", 14, "bold"), fg=CLR["text"], bg=CLR["surface"]).pack()
    tk.Label(hdr, text="Cisco Packet Tracer PC Command Line 1.0  |  ping + сканування + збереження + аналіз трафіку",
             font=("Consolas", 9), fg=CLR["subtext"], bg=CLR["surface"]).pack()

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background=CLR["surface"], borderwidth=0)
    style.configure("TNotebook.Tab",
                    background=CLR["overlay"], foreground=CLR["text"],
                    font=("Consolas", 10, "bold"), padding=[14, 6])
    style.map("TNotebook.Tab",
              background=[("selected", CLR["blue"])],
              foreground=[("selected", CLR["surface"])])

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    ping_tab              = tab_ping(nb, root)
    scan_tab, scan_results = tab_scan(nb, root)
    save_tab              = tab_save(nb, root, scan_results)
    traffic_tab           = tab_traffic(nb, root)

    nb.add(ping_tab,      text="  Ping  ")
    nb.add(scan_tab,      text="  Сканування мережі  ")
    nb.add(save_tab,      text="  Збереження результатів  ")
    nb.add(traffic_tab,   text="  🌐 Аналіз трафіку  ")

    root.mainloop()


if __name__ == "__main__":
    build_gui()
