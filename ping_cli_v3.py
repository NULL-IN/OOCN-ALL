"""
ping_cli.py — утиліта пінгування у стилі Cisco Packet Tracer
підтримує: одиночний ping, сканування мережі за CIDR або діапазоном IP
           збереження результатів у файли (active_hosts.txt / inactive_hosts.txt)
працює на Windows та Linux
використовує subprocess, ipaddress для обробки мереж
"""

import subprocess
import re
import sys
import platform
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def parse_time(line):
    """
    витягує час відповіді з рядка ping

    повертає кортеж (час_мс: int, рядок_для_виводу: str)
    """
    line_lower = line.lower()

    # linux: time=12.3 ms або time<1ms
    m = re.search(r"time\s*=\s*([\d.]+)\s*ms", line_lower)
    if m:
        t = float(m.group(1))
        t_int = round(t)
        if t_int == 0:
            return 0, "time<1ms"
        return t_int, f"time={t_int}ms"

    # windows: time=15ms або time<1ms
    m = re.search(r"time\s*(<1|(\d+))\s*ms", line_lower)
    if m:
        if m.group(1) == "<1":
            return 0, "time<1ms"
        t = int(m.group(2))
        return t, f"time={t}ms"

    return 0, "time<1ms"


def ping(host, count=4):
    """
    пінгує хост і виводить кожну відповідь одразу при отриманні
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = f"chcp 437 >nul & ping -n {count} {host}"
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="ascii",
            errors="replace",
            shell=True
        )
        ttl_default = "TTL=128"
    else:
        process = subprocess.Popen(
            ["ping", "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        ttl_default = ""

    print(f"\nPinging {host} with 32 bytes of data:\n")

    times = []
    received = 0

    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if not line:
            continue

        ll = line.lower()

        if "bytes from" in ll or "reply from" in ll:
            received += 1
            t, time_str = parse_time(line)

            ttl_match = re.search(r"ttl[=:]?\s*(\d+)", ll)
            ttl = f"TTL={ttl_match.group(1)}" if ttl_match else ttl_default

            ip_match = re.search(r"from\s+([0-9a-f:.]+)", ll)
            from_ip = ip_match.group(1) if ip_match else host

            times.append(t)
            print(f"Reply from {from_ip}: bytes=32 {time_str} {ttl}")

        elif "request timed out" in ll or "timed out" in ll:
            print("Request timed out.")

        elif "destination host unreachable" in ll or "unreachable" in ll:
            print(f"Reply from {host}: Destination host unreachable.")

    process.wait()

    lost = count - received
    loss_pct = int((lost / count) * 100) if count > 0 else 0

    print(f"\nPing statistics for {host}:")
    print(f"    Packets: Sent = {count}, Received = {received}, Lost = {lost} ({loss_pct}% loss),")

    if times:
        min_t = min(times)
        max_t = max(times)
        avg_t = round(sum(times) / len(times))
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min_t}ms, Maximum = {max_t}ms, Average = {avg_t}ms")
    print()


def ping_once_ms(host):
    """
    пінгує хост один раз, повертає час відповіді в мс або -1 якщо недоступний
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "800", host]
        enc = "ascii"
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
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


def save_results(active, inactive, filename_active="active_hosts.txt", filename_inactive="inactive_hosts.txt"):
    """
    зберігає результати сканування у два файли
    active   – список рядків вигляду (ip, ms)
    inactive – список ip-рядків
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filename_active, "w", encoding="utf-8") as f:
        f.write(f"# Активні хости — {timestamp}\n")
        f.write(f"# Всього: {len(active)}\n\n")
        for ip, ms in active:
            ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
            f.write(f"{ip:<20} {ms_str}\n")

    with open(filename_inactive, "w", encoding="utf-8") as f:
        f.write(f"# Неактивні хости — {timestamp}\n")
        f.write(f"# Всього: {len(inactive)}\n\n")
        for ip in inactive:
            f.write(f"{ip}\n")

    print(f"\nРезультати збережено:")
    print(f"  Активні   → {filename_active}  ({len(active)} хостів)")
    print(f"  Неактивні → {filename_inactive}  ({len(inactive)} хостів)")


def scan_network(network_str, use_mask=False, mask_str=None, save=False):
    """
    сканує мережу або діапазон IP і виводить доступні хости

    network_str — може бути:
      - cidr: "192.168.1.0/24"
      - діапазон: "192.168.1.1-192.168.1.50"
      - просто мережа без маски

    use_mask — якщо True, використовує mask_str для побудови мережі
    mask_str  — маска підмережі, напр. "255.255.255.0"
    save      — якщо True, зберігає результати у файли
    """
    hosts = []

    MAX_HOSTS = 2048

    try:
        # режим з маскою
        if use_mask and mask_str:
            net = ipaddress.IPv4Network(f"{network_str}/{mask_str}", strict=False)
            total = net.num_addresses - 2
            if total > MAX_HOSTS:
                print(f"Помилка: мережа містить {total} хостів — максимум {MAX_HOSTS}. Вкажіть меншу підмережу.")
                return
            hosts = list(net.hosts())
            print(f"\nСканування мережі {net} (маска: {net.netmask})")
            print(f"Діапазон хостів: {hosts[0]} – {hosts[-1]}")
            print(f"Всього хостів: {len(hosts)}\n")

        elif "/" in network_str:
            net = ipaddress.IPv4Network(network_str, strict=False)
            total = net.num_addresses - 2
            if total > MAX_HOSTS:
                print(f"Помилка: мережа містить {total} хостів — максимум {MAX_HOSTS}.")
                print(f"  Підказка: /24 = 254 хости, /23 = 510, /22 = 1022, /21 = 2046")
                return
            hosts = list(net.hosts())
            print(f"\nСканування мережі {net} (маска: {net.netmask})")
            print(f"Діапазон хостів: {hosts[0]} – {hosts[-1]}")
            print(f"Всього хостів: {len(hosts)}\n")

        elif "-" in network_str:
            parts = network_str.split("-")
            start_ip = ipaddress.IPv4Address(parts[0].strip())
            end_ip   = ipaddress.IPv4Address(parts[1].strip())
            total = int(end_ip) - int(start_ip) + 1
            if total > MAX_HOSTS:
                print(f"Помилка: діапазон містить {total} хостів — максимум {MAX_HOSTS}.")
                return
            current = start_ip
            while current <= end_ip:
                hosts.append(current)
                current += 1
            print(f"\nСканування діапазону: {start_ip} – {end_ip}")
            print(f"Всього хостів: {len(hosts)}\n")

        else:
            net = ipaddress.IPv4Network(f"{network_str}/24", strict=False)
            hosts = list(net.hosts())
            print(f"\nСканування мережі {net} (маска: {net.netmask}, за замовчуванням /24)")
            print(f"Діапазон хостів: {hosts[0]} – {hosts[-1]}")
            print(f"Всього хостів: {len(hosts)}\n")

    except ValueError as e:
        print(f"Помилка адреси: {e}")
        return

    if len(hosts) > 254:
        ans = input(f"Хостів {len(hosts)} — сканування займе більше часу. Продовжити? [y/N]: ")
        if ans.lower() != "y":
            print("Скасовано.")
            return

    print(f"{'IP-адреса':<20} {'Статус':<8} Затримка")
    print("-" * 40)

    alive = []    # список (ip_str, ms)
    dead  = []    # список ip_str
    lock = threading.Lock()

    def check(host):
        ip_str = str(host)
        ms = ping_once_ms(ip_str)
        with lock:
            if ms >= 0:
                ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                color_ok  = "\033[92m"
                color_end = "\033[0m"
                print(f"{color_ok}{ip_str:<20} {'Up':<8} {ms_str}{color_end}", flush=True)
                alive.append((ip_str, ms))
            else:
                color_dn  = "\033[91m"
                color_end = "\033[0m"
                print(f"{color_dn}{ip_str:<20} {'Down':<8} —{color_end}", flush=True)
                dead.append(ip_str)

    # паралельне сканування (до 50 потоків)
    max_workers = min(50, len(hosts))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, h): h for h in hosts}
        for f in as_completed(futures):
            pass

    # ── підсумкова таблиця ────────────────────────────────────────────────────
    print("-" * 35)
    print(f"\n{'Активних хостів':<22} {len(alive)}")
    print(f"{'Неактивних хостів':<22} {len(dead)}")
    print(f"{'Всього перевірено':<22} {len(hosts)}\n")

    if alive:
        print("Активні хости (відсортовано):")
        for ip, ms in sorted(alive, key=lambda x: ipaddress.IPv4Address(x[0])):
            ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
            print(f"  \033[92m✔\033[0m  {ip:<20} {ms_str}")

    if dead:
        print("\nНеактивні хости:")
        for ip in sorted(dead, key=lambda x: ipaddress.IPv4Address(x)):
            print(f"  \033[91m✘\033[0m  {ip}")

    # збереження у файли
    if save:
        save_results(alive, dead)
    else:
        ans = input("\nЗберегти результати у файли? [y/N]: ")
        if ans.lower() == "y":
            save_results(alive, dead)

    print()


def main():
    print("Cisco Packet Tracer PC Command Line 1.0")
    print("Команди: ping <хост> [-n <к-сть>] | scan <мережа/cidr або діапазон> [-m <маска>] [-s] | exit\n")

    if len(sys.argv) >= 2:
        host = sys.argv[1]
        count = int(sys.argv[2]) if len(sys.argv) >= 3 else 4
        print(f"C:\\>ping {host}")
        ping(host, count)
        return

    # інтерактивний режим
    while True:
        try:
            command = input("C:\\>").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not command:
            continue

        parts = command.split()
        cmd = parts[0].lower()

        # ────────── команда ping ──────────
        if cmd == "ping":
            if len(parts) < 2:
                print("Використання: ping <хост> [-n <кількість>]")
                continue

            host = None
            count = 4
            i = 1
            while i < len(parts):
                if parts[i].lower() in ("-n", "-c"):
                    if i + 1 < len(parts):
                        try:
                            count = int(parts[i + 1])
                        except ValueError:
                            print("Помилка: кількість має бути числом")
                            break
                        i += 2
                    else:
                        print("Помилка: після -n/-c очікується число")
                        break
                else:
                    host = parts[i]
                    i += 1

            if host:
                ping(host, count)
            else:
                print("Використання: ping <хост> [-n <кількість>]")

        # ────────── команда scan ──────────
        elif cmd == "scan":
            if len(parts) < 2:
                print("Використання: scan <мережа> [-m <маска>] [-s]")
                print("  Прапори:")
                print("    -m <маска>  — маска підмережі")
                print("    -s          — автоматично зберегти результати у файли")
                print("  Приклади:")
                print("    scan 192.168.1.0/24")
                print("    scan 192.168.1.1-192.168.1.50")
                print("    scan 192.168.1.0 -m 255.255.255.0 -s")
                continue

            network_str = parts[1]
            use_mask = False
            mask_str = None
            save = False

            # прапор -m
            if "-m" in [p.lower() for p in parts]:
                idx = [p.lower() for p in parts].index("-m")
                if idx + 1 < len(parts):
                    mask_str = parts[idx + 1]
                    use_mask = True
                else:
                    print("Помилка: після -m очікується маска")
                    continue

            # прапор -s (автозбереження)
            if "-s" in [p.lower() for p in parts]:
                save = True

            scan_network(network_str, use_mask, mask_str, save)

        elif cmd in ("exit", "quit", "q"):
            break

        else:
            print(f"'{parts[0]}' не є внутрішньою або зовнішньою командою.")


if __name__ == "__main__":
    main()
