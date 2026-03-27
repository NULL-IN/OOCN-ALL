"""
ping_gui.py – графічна утиліта пінгування v2
підтримує: одиночний ping + сканування мережі (cidr, діапазон, маска)
працює на Windows / Linux / macOS (tkinter + subprocess)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import re
import threading
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


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
}


# ══════════════════════════════════════════════════════════════════════════════
#  утиліти ping
# ══════════════════════════════════════════════════════════════════════════════

def parse_reply_line(line):
    """парсить рядок виводу ping, повертає (час_мс | None, текст_для_виводу | None)"""
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
        # повторний пошук для icmp_seq
        m = re.search(r"icmp_seq=\d+.*time[=<]([\d.]+)\s*ms", ll)
        if m:
            t = round(float(m.group(1)))
            return t, f"time={t}ms" if t > 0 else "time<1ms"

    return None, None


def ping_once_ms(ip_str):
    """
    пінгує хост один раз, повертає час відповіді в мс або -1 якщо недоступний
    використовується для сканування мережі
    """
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
        # витягуємо час з виводу
        out = r.stdout.lower()
        m = re.search(r"time[=<]([\d.]+)\s*ms", out)
        if m:
            return round(float(m.group(1)))
        # time<1ms — вважаємо 0
        if "time<1ms" in out or "time <1ms" in out:
            return 0
        return 0  # відповів але час не знайдено
    except Exception:
        return -1


MAX_HOSTS = 2048


def build_host_list(network_str, use_mask, mask_str):
    """
    будує список IPv4Address для сканування
    підтримує: cidr, діапазон через -, або мережа + маска окремо
    викидає ValueError якщо хостів більше MAX_HOSTS
    """
    if use_mask and mask_str:
        # якщо в полі є /xx — відкидаємо, бо маска задана окремо
        base_ip = network_str.split("/")[0].strip()
        net = ipaddress.IPv4Network(f"{base_ip}/{mask_str}", strict=False)
        total = net.num_addresses - 2
        if total > MAX_HOSTS:
            raise ValueError(f"Мережа містить {total} хостів — максимум {MAX_HOSTS}.\nВкажіть меншу підмережу (наприклад /24 = 254 хости).")
        return list(net.hosts()), str(net), str(net.netmask)

    if "/" in network_str:
        net = ipaddress.IPv4Network(network_str, strict=False)
        total = net.num_addresses - 2
        if total > MAX_HOSTS:
            raise ValueError(f"Мережа містить {total} хостів — максимум {MAX_HOSTS}.\nПідказка: /24 = 254, /23 = 510, /22 = 1022, /21 = 2046")
        return list(net.hosts()), str(net), str(net.netmask)

    if "-" in network_str:
        parts = network_str.split("-")
        start = ipaddress.IPv4Address(parts[0].strip())
        end   = ipaddress.IPv4Address(parts[1].strip())
        total = int(end) - int(start) + 1
        if total > MAX_HOSTS:
            raise ValueError(f"Діапазон містить {total} хостів — максимум {MAX_HOSTS}.")
        hosts = []
        cur = start
        while cur <= end:
            hosts.append(cur)
            cur += 1
        return hosts, f"{start} – {end}", "—"

    # без маски — беремо /24 за замовчуванням
    net = ipaddress.IPv4Network(f"{network_str}/24", strict=False)
    return list(net.hosts()), str(net), str(net.netmask)


def make_readonly(widget):
    """
    робить Text/ScrolledText read-only але з можливістю виділяти і копіювати
    блокує введення клавіатурою, дозволяє ctrl+c, ctrl+a, стрілки
    """
    def _block(e):
        # пропускаємо ctrl+c, ctrl+a, ctrl+x (копіювання/виділення)
        if e.state & 0x4 and e.keysym.lower() in ('c', 'a', 'x'):
            return None
        # пропускаємо навігаційні клавіші
        if e.keysym in ('Up', 'Down', 'Left', 'Right', 'Home', 'End',
                        'Prior', 'Next', 'Shift_L', 'Shift_R',
                        'Control_L', 'Control_R'):
            return None
        return "break"

    widget.bind("<Key>", _block)
    widget.bind("<<Paste>>", lambda e: "break")
    widget.config(cursor="arrow")


# ══════════════════════════════════════════════════════════════════════════════
#  вкладка 1 — одиночний ping
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
        # chcp 437 форсує ASCII-виведення, щоб уникнути кириличного сміття
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
            ("Надіслано", count,           CLR["green"]),
            ("Отримано",  received,        CLR["blue"]),
            ("Втрачено",  lost,            CLR["red"]),
            ("Мін. час",  f"{mn} мс",      CLR["mauve"]),
            ("Макс. час", f"{mx} мс",      CLR["peach"]),
            ("Сер. час",  f"{av} мс",      CLR["teal"]),
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

    # панель вводу
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

    # термінал
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
            count = int(count_var.get())
            count = max(1, min(count, 100))
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
#  вкладка 2 — сканування мережі
# ══════════════════════════════════════════════════════════════════════════════

def tab_scan(notebook, root):
    frame = tk.Frame(notebook, bg=CLR["bg"])

    # ── рядок 1: мережа / CIDR / діапазон ────────────────────────────────
    row1 = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=8)
    row1.pack(fill="x")

    tk.Label(row1, text="Мережа / CIDR / діапазон:", font=("Consolas", 10),
             fg=CLR["text"], bg=CLR["bg"]).grid(row=0, column=0, sticky="w", padx=(0, 8))

    net_var = tk.StringVar(value="192.168.1.0/24")
    net_entry = tk.Entry(row1, textvariable=net_var, font=("Consolas", 11),
                         bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
                         relief="flat", width=30)
    net_entry.grid(row=0, column=1, ipady=4, padx=(0, 20))

    # ── рядок 2: маска (вмикається чекбоксом) ─────────────────────────────
    row2 = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=0)
    row2.pack(fill="x")

    use_mask_var = tk.BooleanVar(value=False)
    mask_chk = tk.Checkbutton(
        row2, text="Вказати маску окремо", variable=use_mask_var,
        font=("Consolas", 10), fg=CLR["text"], bg=CLR["bg"],
        activebackground=CLR["bg"], activeforeground=CLR["blue"],
        selectcolor=CLR["overlay"], cursor="hand2"
    )
    mask_chk.grid(row=0, column=0, sticky="w")

    mask_var = tk.StringVar(value="255.255.255.0")
    mask_entry = tk.Entry(row2, textvariable=mask_var, font=("Consolas", 11),
                          bg=CLR["overlay"], fg=CLR["text"], insertbackground=CLR["text"],
                          relief="flat", width=18, state="disabled")
    mask_entry.grid(row=0, column=1, ipady=4, padx=(12, 0))

    # вмикаємо/вимикаємо поле маски
    def toggle_mask(*_):
        mask_entry.config(state="normal" if use_mask_var.get() else "disabled")
    use_mask_var.trace_add("write", toggle_mask)

    # ── рядок 3: кнопка + прогрес ─────────────────────────────────────────
    row3 = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=8)
    row3.pack(fill="x")

    btn_scan = tk.Button(row3, text="  Сканувати  ", font=("Consolas", 11, "bold"),
                         bg=CLR["mauve"], fg=CLR["surface"], activebackground=CLR["blue"],
                         relief="flat", padx=10, pady=4, cursor="hand2")
    btn_scan.grid(row=0, column=0, padx=(0, 20))

    progress_var = tk.DoubleVar(value=0)
    progress_lbl = tk.Label(row3, text="", font=("Consolas", 9),
                            fg=CLR["subtext"], bg=CLR["bg"])
    progress_lbl.grid(row=0, column=1, sticky="w")

    progress_bar = ttk.Progressbar(row3, variable=progress_var, maximum=100, length=300)
    progress_bar.grid(row=0, column=2, padx=(10, 0))

    # ── термінал виводу ────────────────────────────────────────────────────
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

    # ── підсумкові картки ──────────────────────────────────────────────────
    summary_frame = tk.Frame(frame, bg=CLR["bg"], padx=16, pady=6)
    summary_frame.pack(fill="x")

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

        # очищення
        output.config(state="normal")
        output.delete("1.0", tk.END)
        output.config(state="disabled")
        for w in summary_frame.winfo_children():
            w.destroy()
        progress_var.set(0)
        progress_lbl.config(text="")

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

            alive = []
            done_count = [0]
            lock = threading.Lock()

            def check(host_addr):
                ip_str = str(host_addr)
                ms = ping_once_ms(ip_str)
                with lock:
                    done_count[0] += 1
                    pct = done_count[0] / len(hosts) * 100
                    progress_var.set(pct)
                    progress_lbl.config(text=f"{done_count[0]}/{len(hosts)}")
                    if ms >= 0:
                        ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                        alive.append(ip_str)
                        append(f"{ip_str:<22} {'Up':<10} {ms_str}", "up")
                    else:
                        append(f"{ip_str:<22} {'Down':<10} —", "down")

            max_workers = min(50, len(hosts))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(check, h): h for h in hosts}
                for f in as_completed(futures):
                    pass

            # підсумок
            append("─" * 38, "summary")
            append(f"\nЗнайдено {len(alive)} активних / {len(hosts)} хостів", "summary")
            if alive:
                append("Активні хости:", "summary")
                for ip in sorted(alive, key=lambda x: ipaddress.IPv4Address(x)):
                    append(f"  ✔  {ip}", "up")

            # картки підсумку
            summary_cards = [
                ("Перевірено",  len(hosts),        CLR["blue"]),
                ("Активних",    len(alive),         CLR["green"]),
                ("Недоступних", len(hosts)-len(alive), CLR["red"]),
            ]
            for i, (lbl, val, col) in enumerate(summary_cards):
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
    return frame


# ══════════════════════════════════════════════════════════════════════════════
#  головне вікно
# ══════════════════════════════════════════════════════════════════════════════

def build_gui():
    root = tk.Tk()
    root.title("Ping Utility v2 – Cisco Packet Tracer Style")
    root.geometry("820x600")
    root.minsize(700, 500)
    root.configure(bg=CLR["surface"])

    # заголовок
    hdr = tk.Frame(root, bg=CLR["surface"], pady=10)
    hdr.pack(fill="x")
    tk.Label(hdr, text="Ping Utility v2",
             font=("Consolas", 14, "bold"), fg=CLR["text"], bg=CLR["surface"]).pack()
    tk.Label(hdr, text="Cisco Packet Tracer PC Command Line 1.0  |  одиночний ping + сканування мережі",
             font=("Consolas", 9), fg=CLR["subtext"], bg=CLR["surface"]).pack()

    # вкладки
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook",
                    background=CLR["surface"], borderwidth=0)
    style.configure("TNotebook.Tab",
                    background=CLR["overlay"], foreground=CLR["text"],
                    font=("Consolas", 10, "bold"), padding=[14, 6])
    style.map("TNotebook.Tab",
              background=[("selected", CLR["blue"])],
              foreground=[("selected", CLR["surface"])])

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    nb.add(tab_ping(nb, root), text="  Ping  ")
    nb.add(tab_scan(nb, root), text="  Сканування мережі  ")

    root.mainloop()


if __name__ == "__main__":
    build_gui()