"""
ping_cli.py — утиліта пінгування v4 (Cisco Packet Tracer style)
підтримує: ping, scan (збереження), capture (аналіз живого трафіку)
capture потребує: pip install scapy + Npcap (npcap.com) + Адміністратор
"""

import subprocess
import re
import sys
import platform
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Аналіз трафіку (Raw Sockets) ──────────────────────────────────────────
# Використовуємо вбудовані "сирі сокети" Windows (без сторонніх npcap/scapy)
import socket
import struct
import os

# ── ANSI кольори ───────────────────────────────────────────────────────────
G   = "\033[92m"   # зелений
R   = "\033[91m"   # червоний
B   = "\033[94m"   # синій
Y   = "\033[93m"   # жовтий
M   = "\033[95m"   # пурпурний
C   = "\033[96m"   # блакитний (ICMP)
ORG = "\033[38;5;214m"  # оранжевий (SSH)
DIM = "\033[2m"
RST = "\033[0m"

PROTO_CLR = {
    "icmp": C, "tcp": G, "udp": B,
    "http": Y, "https": Y, "dns": M, "ssh": ORG, "other": DIM,
}


# ══════════════════════════════════════════════════════════════════════════════
#  функції ping (з v3, без змін)
# ══════════════════════════════════════════════════════════════════════════════

def parse_time(line):
    line_lower = line.lower()
    m = re.search(r"time\s*=\s*([\d.]+)\s*ms", line_lower)
    if m:
        t = float(m.group(1))
        t_int = round(t)
        return 0, "time<1ms" if t_int == 0 else (t_int, f"time={t_int}ms")[1], t_int
    m = re.search(r"time\s*(<1|(\d+))\s*ms", line_lower)
    if m:
        if m.group(1) == "<1":
            return 0, "time<1ms"
        t = int(m.group(2))
        return t, f"time={t}ms"
    return 0, "time<1ms"


# виправлена версія parse_time, сумісна зі старим кодом
def _parse_time_v3(line):
    line_lower = line.lower()
    m = re.search(r"time\s*=\s*([\d.]+)\s*ms", line_lower)
    if m:
        t = float(m.group(1))
        t_int = round(t)
        if t_int == 0:
            return 0, "time<1ms"
        return t_int, f"time={t_int}ms"
    m = re.search(r"time\s*(<1|(\d+))\s*ms", line_lower)
    if m:
        if m.group(1) == "<1":
            return 0, "time<1ms"
        t = int(m.group(2))
        return t, f"time={t}ms"
    return 0, "time<1ms"


def ping(host, count=4):
    system = platform.system().lower()
    if system == "windows":
        cmd = f"chcp 437 >nul & ping -n {count} {host}"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="ascii", errors="replace", shell=True)
        ttl_default = "TTL=128"
    else:
        process = subprocess.Popen(["ping", "-c", str(count), host],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace")
        ttl_default = ""

    print(f"\nPinging {host} with 32 bytes of data:\n")
    times, received = [], 0

    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if not line:
            continue
        ll = line.lower()
        if "bytes from" in ll or "reply from" in ll:
            received += 1
            t, time_str = _parse_time_v3(line)
            ttl_match = re.search(r"ttl[=:]?\s*(\d+)", ll)
            ttl = f"TTL={ttl_match.group(1)}" if ttl_match else ttl_default
            ip_match = re.search(r"from\s+([0-9a-f:.]+)", ll)
            from_ip = ip_match.group(1) if ip_match else host
            times.append(t)
            print(f"{G}Reply from {from_ip}: bytes=32 {time_str} {ttl}{RST}")
        elif "request timed out" in ll or "timed out" in ll:
            print(f"{R}Request timed out.{RST}")
        elif "unreachable" in ll:
            print(f"{R}Reply from {host}: Destination host unreachable.{RST}")
    process.wait()

    lost = count - received
    loss_pct = int((lost / count) * 100) if count > 0 else 0
    print(f"\nPing statistics for {host}:")
    print(f"    Packets: Sent = {count}, Received = {received}, Lost = {lost} ({loss_pct}% loss),")
    if times:
        mn, mx, av = min(times), max(times), round(sum(times) / len(times))
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {mn}ms, Maximum = {mx}ms, Average = {av}ms")
    print()


def ping_once_ms(host):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "800", host]
        enc = "ascii"
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
        enc = "utf-8"
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=4, encoding=enc, errors="replace")
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


def save_results(active, inactive,
                 filename_active="active_hosts.txt",
                 filename_inactive="inactive_hosts.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename_active, "w", encoding="utf-8") as f:
        f.write(f"# активні хости — {timestamp}\n# всього: {len(active)}\n\n")
        for ip, ms in active:
            ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
            f.write(f"{ip:<20} {ms_str}\n")
    with open(filename_inactive, "w", encoding="utf-8") as f:
        f.write(f"# неактивні хости — {timestamp}\n# всього: {len(inactive)}\n\n")
        for ip in inactive:
            f.write(f"{ip}\n")
    print(f"\nРезультати збережено:")
    print(f"  Активні   → {filename_active}  ({len(active)} хостів)")
    print(f"  Неактивні → {filename_inactive}  ({len(inactive)} хостів)")


def scan_network(network_str, use_mask=False, mask_str=None, save=False):
    hosts = []
    MAX_HOSTS = 2048
    try:
        if use_mask and mask_str:
            net = ipaddress.IPv4Network(f"{network_str}/{mask_str}", strict=False)
            total = net.num_addresses - 2
            if total > MAX_HOSTS:
                print(f"Помилка: мережа містить {total} хостів — максимум {MAX_HOSTS}.")
                return
            hosts = list(net.hosts())
            print(f"\nСканування мережі {net} (маска: {net.netmask})")
            print(f"Всього хостів: {len(hosts)}\n")
        elif "/" in network_str:
            net = ipaddress.IPv4Network(network_str, strict=False)
            total = net.num_addresses - 2
            if total > MAX_HOSTS:
                print(f"Помилка: мережа містить {total} хостів — максимум {MAX_HOSTS}.")
                return
            hosts = list(net.hosts())
            print(f"\nСканування мережі {net} (маска: {net.netmask})")
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
            print(f"\nСканування мережі {net} (маска: {net.netmask}, /24 за замовчуванням)")
            print(f"Всього хостів: {len(hosts)}\n")
    except ValueError as e:
        print(f"Помилка адреси: {e}")
        return

    if len(hosts) > 254:
        ans = input(f"Хостів {len(hosts)} — займе більше часу. Продовжити? [y/N]: ")
        if ans.lower() != "y":
            print("Скасовано.")
            return

    print(f"{'IP-адреса':<20} {'Статус':<8} Затримка")
    print("-" * 40)

    alive, dead = [], []
    lock = threading.Lock()

    def check(host):
        ip_str = str(host)
        ms = ping_once_ms(ip_str)
        with lock:
            if ms >= 0:
                ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
                print(f"{G}{ip_str:<20} {'Up':<8} {ms_str}{RST}", flush=True)
                alive.append((ip_str, ms))
            else:
                print(f"{R}{ip_str:<20} {'Down':<8} —{RST}", flush=True)
                dead.append(ip_str)

    with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as executor:
        for f in as_completed({executor.submit(check, h): h for h in hosts}):
            pass

    print("-" * 35)
    print(f"\n{'Активних хостів':<22} {len(alive)}")
    print(f"{'Неактивних хостів':<22} {len(dead)}")
    print(f"{'Всього перевірено':<22} {len(hosts)}\n")

    if alive:
        print("Активні хости (відсортовано):")
        for ip, ms in sorted(alive, key=lambda x: ipaddress.IPv4Address(x[0])):
            ms_str = f"{ms} мс" if ms > 0 else "<1 мс"
            print(f"  {G}✔{RST}  {ip:<20} {ms_str}")
    if dead:
        print("\nНеактивні хости:")
        for ip in sorted(dead, key=lambda x: ipaddress.IPv4Address(x)):
            print(f"  {R}✘{RST}  {ip}")

    if save:
        save_results(alive, dead)
    else:
        ans = input("\nЗберегти результати у файли? [y/N]: ")
        if ans.lower() == "y":
            save_results(alive, dead)
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  НОВІ функції — аналіз живого трафіку (v4)
# ══════════════════════════════════════════════════════════════════════════════

_cap_stop    = threading.Event()
_cap_packets = []
_cap_counter = [0]
_cap_lock    = threading.Lock()
_cap_filter_proto = None
_cap_filter_ip    = None


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

def _print_cap_header():
    print(f"{B}{'#':<5} {'Час':<13} {'Джерело':<18} {'Призначення':<18} "
          f"{'Протокол':<8} {'Довж.':<7} Інформація{RST}")
    print("─" * 90)

def do_capture(proto_filter=None, ip_filter=None, count=0):
    global _cap_filter_proto, _cap_filter_ip

    _cap_filter_proto = [p.lower() for p in proto_filter] if proto_filter else None
    _cap_filter_ip    = ip_filter
    _cap_stop.clear()
    _cap_packets.clear()
    _cap_counter[0] = 0

    print(f"\n{G}Запуск захоплення трафіку (вбудований сніфер)...{RST}")
    if _cap_filter_proto:
        print(f"  Протоколи : {', '.join(_cap_filter_proto).upper()}")
    if _cap_filter_ip:
        print(f"  Фільтр IP : {_cap_filter_ip}")
    if count:
        print(f"  Кількість : {count}")
    print(f"{DIM}Натисни Ctrl+C або введи 'stop' щоб зупинити{RST}\n")
    _print_cap_header()

    def worker():
        sock = None
        try:
            local_ip = _get_local_ip()
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if os.name == 'nt':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while not _cap_stop.is_set():
                if count > 0 and _cap_counter[0] >= count:
                    break
                sock.settimeout(1.0)
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                p = _parse_raw_packet(data)
                if not p:
                    continue

                if _cap_filter_proto and p["proto"] not in _cap_filter_proto:
                    continue
                if _cap_filter_ip and _cap_filter_ip not in (p["src"], p["dst"]):
                    continue

                with _cap_lock:
                    _cap_counter[0] += 1
                    n = _cap_counter[0]
                    _cap_packets.append(p)
                
                col = PROTO_CLR.get(p["proto"], DIM)
                print(f"{col}{n:<5} {p['time']:<13} {p['src']:<18} {p['dst']:<18} "
                      f"{p['proto'].upper():<8} {p['len']:<7} {p['info']}{RST}", flush=True)

        except OSError as e:
            if getattr(e, "winerror", 0) == 10013 or "access denied" in str(e).lower() or "доступу" in str(e).lower():
                print(f"\n{R}Помилка доступу: {e}{RST}")
                print(f"{R}► Сніфер вимагає запуску консолі від імені АДМІНІСТРАТОРА!{RST}")
            else:
                print(f"\n{R}Помилка сокета: {e}{RST}")
        except Exception as e:
            print(f"\n{R}Помилка захоплення: {e}{RST}")
        finally:
            if sock and os.name == 'nt':
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            if sock:
                sock.close()
            print(f"\n{G}Захоплення завершено. Пакетів: {_cap_counter[0]}{RST}")

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


def stop_capture():
    _cap_stop.set()


def print_cap_stats():
    from collections import Counter
    if not _cap_packets:
        print("Немає захоплених пакетів.")
        return
    cnt = Counter(p["proto"] for p in _cap_packets)
    print(f"\n{B}Статистика ({_cap_counter[0]} пакетів):{RST}")
    print("─" * 35)
    for proto, n in cnt.most_common():
        col = PROTO_CLR.get(proto, DIM)
        bar = "█" * min(n, 40)
        print(f"  {col}{proto:<10}{RST} {n:>5}  {B}{bar}{RST}")
    print()


def save_capture(filename="capture.txt"):
    if not _cap_packets:
        print("Немає захоплених пакетів для збереження.")
        return
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# захоплення трафіку — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# пакетів: {len(_cap_packets)}\n\n")
        f.write(f"{'#':<5} {'Час':<13} {'Джерело':<18} {'Призначення':<18} "
                f"{'Протокол':<10} {'Довж.':<7} Інформація\n")
        f.write("─" * 88 + "\n")
        for i, p in enumerate(_cap_packets, 1):
            f.write(f"{i:<5} {p['time']:<13} {p['src']:<18} {p['dst']:<18} "
                    f"{p['proto'].upper():<10} {p['len']:<7} {p['info']}\n")
    print(f"{G}Збережено → {filename}  ({len(_cap_packets)} пакетів){RST}")


# ══════════════════════════════════════════════════════════════════════════════
#  головна функція
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("Cisco Packet Tracer PC Command Line 1.0")
    print("Команди: ping | scan | capture | stop | stats | save | help | exit\n")

    # аргументний режим (ping <host>)
    if len(sys.argv) >= 2:
        host  = sys.argv[1]
        count = int(sys.argv[2]) if len(sys.argv) >= 3 else 4
        print(f"C:\\>ping {host}")
        ping(host, count)
        return

    cap_thread = None

    while True:
        try:
            command = input("C:\\>").strip()
        except (EOFError, KeyboardInterrupt):
            stop_capture()
            print()
            break
        if not command:
            continue

        parts = command.split()
        cmd   = parts[0].lower()

        # ────────── ping ──────────
        if cmd == "ping":
            if len(parts) < 2:
                print("Використання: ping <хост> [-n <кількість>]")
                continue
            host  = None
            count = 4
            i = 1
            while i < len(parts):
                if parts[i].lower() in ("-n", "-c"):
                    if i + 1 < len(parts):
                        try:
                            count = int(parts[i + 1])
                        except ValueError:
                            print("Помилка: кількість має бути числом")
                        i += 2
                    else:
                        i += 1
                else:
                    host = parts[i]
                    i += 1
            if host:
                ping(host, count)
            else:
                print("Використання: ping <хост> [-n <кількість>]")

        # ────────── scan ──────────
        elif cmd == "scan":
            if len(parts) < 2:
                print("Використання: scan <мережа> [-m <маска>] [-s]")
                print("  Приклади:")
                print("    scan 192.168.1.0/24")
                print("    scan 192.168.1.1-192.168.1.50")
                print("    scan 192.168.1.0 -m 255.255.255.0 -s")
                continue
            network_str = parts[1]
            use_mask = False
            mask_str = None
            save     = False
            pl = [p.lower() for p in parts]
            if "-m" in pl:
                idx = pl.index("-m")
                if idx + 1 < len(parts):
                    mask_str = parts[idx + 1]
                    use_mask = True
            if "-s" in pl:
                save = True
            scan_network(network_str, use_mask, mask_str, save)

        # ────────── capture (НОВА команда v4) ──────────
        elif cmd in ("capture", "cap", "sniff"):
            if len(parts) >= 2 and parts[1].lower() in ("help", "?"):
                print("\nЗахоплення живого трафіку (аналог Wireshark):")
                print("  capture [-proto tcp,http,dns,...] [-ip <адреса>] [-n <к-сть>]")
                print("  Протоколи: tcp  udp  http  https  dns  icmp  ssh")
                print("  -proto all  — всі протоколи (за замовчуванням)")
                print("  Приклади:")
                print("    capture")
                print("    capture -proto dns,http")
                print("    capture -ip 8.8.8.8 -n 20")
                print("  Зупинити: stop  або  Ctrl+C\n")
                continue

            proto_f = None
            ip_f    = None
            count   = 0
            i = 1
            while i < len(parts):
                flag = parts[i].lower()
                if flag == "-proto" and i + 1 < len(parts):
                    v = parts[i+1].lower()
                    proto_f = None if v == "all" else [x.strip() for x in v.split(",")]
                    i += 2
                elif flag == "-ip" and i + 1 < len(parts):
                    ip_f = parts[i+1]
                    i += 2
                elif flag == "-n" and i + 1 < len(parts):
                    try:
                        count = int(parts[i+1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1

            if cap_thread and cap_thread.is_alive():
                print("Захоплення вже запущено. Введи 'stop' щоб зупинити.")
            else:
                cap_thread = do_capture(proto_f, ip_f, count)

        elif cmd == "stop":
            stop_capture()

        elif cmd == "stats":
            print_cap_stats()

        elif cmd == "save":
            fname = parts[1] if len(parts) > 1 else "capture.txt"
            save_capture(fname)

        elif cmd == "help":
            print(f"\n{B}Команди:{RST}")
            print(f"  ping <хост> [-n <к-сть>]       — пінг хоста")
            print(f"  scan <мережа> [-m <маска>] [-s] — сканування мережі")
            print(f"  capture [-proto ...] [-ip ...] [-n <к-сть>]  — аналіз трафіку")
            print(f"  capture help                    — допомога по capture")
            print(f"  stop                            — зупинити захоплення")
            print(f"  stats                           — статистика пакетів")
            print(f"  save [файл]                     — зберегти захоплені пакети")
            print(f"  exit                            — вихід\n")

        elif cmd in ("exit", "quit", "q"):
            stop_capture()
            break

        else:
            print(f"'{parts[0]}' не є внутрішньою або зовнішньою командою.")
            print("Введи 'help' для списку команд.")


if __name__ == "__main__":
    main()
