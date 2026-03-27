"""
ping_gui.py – графічна утиліта пінгування у стилі cisco packet tracer
використовує бібліотеки tkinter (стандартна) та subprocess
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import re
import threading
import platform


def parse_time(line):
    """
    витягує час відповіді з рядка ping

    повертає кортеж (час_мс, рядок_для_виводу)
    """
    if re.search(r"time<1ms", line, re.IGNORECASE):
        return 0, "time<1ms"

    m = re.search(r"time=(\d+)ms", line, re.IGNORECASE)
    if m:
        t = int(m.group(1))
        return t, f"time={t}ms"

    m = re.search(r"time=([\d.]+)\s*ms", line, re.IGNORECASE)
    if m:
        t = round(float(m.group(1)))
        return t, f"time={t}ms" if t > 0 else "time<1ms"

    return 0, "time<1ms"


def run_ping(host, count, output_widget, stats_frame, btn_ping, root):
    """
    виконує пінгування у окремому потоці
    кожна відповідь виводиться одразу при отриманні через readline()

    аргументи:
        host         – ip-адреса або доменне ім'я
        count        – кількість пакетів
        output_widget – текстове поле для виводу
        stats_frame  – фрейм для статистики
        btn_ping     – кнопка (блокується під час роботи)
        root         – головне вікно (для thread-safe update)
    """
    system = platform.system().lower()

    def append(text, tag=None):
        """додає рядок у термінал і одразу оновлює gui"""
        output_widget.config(state="normal")
        if tag:
            output_widget.insert(tk.END, text + "\n", tag)
        else:
            output_widget.insert(tk.END, text + "\n")
        output_widget.see(tk.END)
        output_widget.config(state="disabled")
        root.update_idletasks()

    output_widget.config(state="normal")
    output_widget.delete("1.0", tk.END)
    output_widget.config(state="disabled")

    for widget in stats_frame.winfo_children():
        widget.destroy()

    append(f"Pinging {host} with 32 bytes of data:\n", "header")

    # на windows форсуємо англійський вивід через chcp 437
    if system == "windows":
        cmd = f"chcp 437 > nul & ping -n {count} {host}"
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="ascii",
                errors="replace",
                shell=True
            )
        except Exception as e:
            append(f"Помилка запуску: {e}", "error")
            btn_ping.config(state="normal")
            return
    else:
        try:
            process = subprocess.Popen(
                ["ping", "-c", str(count), host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
        except FileNotFoundError:
            append("Помилка: команда ping не знайдена.", "error")
            btn_ping.config(state="normal")
            return

    times = []
    received = 0

    # читаємо рядок за рядком – кожна відповідь з'являється одразу
    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if not line:
            continue

        ll = line.lower()

        if "reply from" in ll:
            received += 1
            t, time_str = parse_time(line)
            times.append(t)
            append(f"Reply from {host}: bytes=32 {time_str} TTL=128", "reply")

        elif "request timed out" in ll:
            append("Request timed out.", "timeout")

        elif "destination host unreachable" in ll:
            append(f"Reply from {host}: Destination host unreachable.", "timeout")

    process.wait()

    lost = count - received
    loss_pct = int((lost / count) * 100)

    append(f"\nPing statistics for {host}:", "header")
    append(f"    Packets: Sent = {count}, Received = {received}, Lost = {lost} ({loss_pct}% loss),")

    if times:
        min_t = min(times)
        max_t = max(times)
        avg_t = round(sum(times) / len(times))
        append("Approximate round trip times in milli-seconds:")
        append(f"    Minimum = {min_t}ms, Maximum = {max_t}ms, Average = {avg_t}ms")

        # картки статистики
        stats = [
            ("Надіслано", count, "#4CAF50"),
            ("Отримано", received, "#2196F3"),
            ("Втрачено", lost, "#f44336"),
            ("Мін. час", f"{min_t} мс", "#9C27B0"),
            ("Макс. час", f"{max_t} мс", "#FF9800"),
            ("Сер. час", f"{avg_t} мс", "#00BCD4"),
        ]
        for i, (label, value, color) in enumerate(stats):
            card = tk.Frame(stats_frame, bg=color, padx=10, pady=6)
            card.grid(row=0, column=i, padx=4, pady=4, sticky="ew")
            stats_frame.columnconfigure(i, weight=1)
            tk.Label(card, text=str(value), font=("Consolas", 16, "bold"),
                     fg="white", bg=color).pack()
            tk.Label(card, text=label, font=("Consolas", 9),
                     fg="white", bg=color).pack()

    btn_ping.config(state="normal")


def start_ping(host_var, count_var, output_widget, stats_frame, btn_ping, root):
    """запускає пінгування у окремому потоці"""
    host = host_var.get().strip()
    if not host:
        return

    try:
        count = int(count_var.get())
        if count < 1 or count > 100:
            raise ValueError
    except ValueError:
        count = 4

    btn_ping.config(state="disabled")
    thread = threading.Thread(
        target=run_ping,
        args=(host, count, output_widget, stats_frame, btn_ping, root),
        daemon=True
    )
    thread.start()


def build_gui():
    """будує головне вікно застосунку"""
    root = tk.Tk()
    root.title("Cisco Packet Tracer – Ping Utility")
    root.geometry("720x560")
    root.resizable(True, True)
    root.configure(bg="#1E1E2E")

    header_frame = tk.Frame(root, bg="#181825", pady=10)
    header_frame.pack(fill="x")
    tk.Label(
        header_frame,
        text="Ping Utility  –  Cisco Packet Tracer Style",
        font=("Consolas", 13, "bold"),
        fg="#CDD6F4",
        bg="#181825"
    ).pack()
    tk.Label(
        header_frame,
        text="Cisco Packet Tracer PC Command Line 1.0",
        font=("Consolas", 9),
        fg="#6C7086",
        bg="#181825"
    ).pack()

    input_frame = tk.Frame(root, bg="#1E1E2E", padx=16, pady=10)
    input_frame.pack(fill="x")

    tk.Label(input_frame, text="Хост / IP:", font=("Consolas", 10),
             fg="#CDD6F4", bg="#1E1E2E").grid(row=0, column=0, sticky="w", padx=(0, 8))

    host_var = tk.StringVar(value="127.0.0.1")
    host_entry = tk.Entry(input_frame, textvariable=host_var, font=("Consolas", 11),
                          bg="#313244", fg="#CDD6F4", insertbackground="#CDD6F4",
                          relief="flat", bd=4, width=28)
    host_entry.grid(row=0, column=1, padx=(0, 16), ipady=4)

    tk.Label(input_frame, text="Кількість пакетів:", font=("Consolas", 10),
             fg="#CDD6F4", bg="#1E1E2E").grid(row=0, column=2, sticky="w", padx=(0, 8))

    count_var = tk.StringVar(value="4")
    count_spin = ttk.Spinbox(input_frame, from_=1, to=100, textvariable=count_var,
                             font=("Consolas", 11), width=6)
    count_spin.grid(row=0, column=3, padx=(0, 16), ipady=4)

    btn_ping = tk.Button(
        input_frame,
        text="Ping",
        font=("Consolas", 11, "bold"),
        bg="#89B4FA",
        fg="#1E1E2E",
        activebackground="#74C7EC",
        activeforeground="#1E1E2E",
        relief="flat",
        padx=14,
        pady=4,
        cursor="hand2"
    )
    btn_ping.grid(row=0, column=4)

    term_frame = tk.Frame(root, bg="#1E1E2E", padx=16)
    term_frame.pack(fill="both", expand=True)

    output = scrolledtext.ScrolledText(
        term_frame,
        font=("Consolas", 10),
        bg="#11111B",
        fg="#CDD6F4",
        insertbackground="#CDD6F4",
        relief="flat",
        state="disabled",
        wrap="word"
    )
    output.pack(fill="both", expand=True, pady=(0, 8))

    output.tag_config("header",  foreground="#89B4FA")
    output.tag_config("reply",   foreground="#A6E3A1")
    output.tag_config("timeout", foreground="#F38BA8")
    output.tag_config("error",   foreground="#F38BA8")

    stats_frame = tk.Frame(root, bg="#1E1E2E", padx=16, pady=6)
    stats_frame.pack(fill="x")

    btn_ping.config(command=lambda: start_ping(
        host_var, count_var, output, stats_frame, btn_ping, root
    ))

    host_entry.bind("<Return>", lambda e: start_ping(
        host_var, count_var, output, stats_frame, btn_ping, root
    ))

    root.mainloop()


if __name__ == "__main__":
    build_gui()
