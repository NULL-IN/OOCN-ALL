#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  Anti-Sniffer v5 — CLI                                      ║
║  Система виявлення підозрілої мережевої активності           ║
║  Організація комп. мереж · Нагорний Ілля · РПЗ-24Б          ║
╚══════════════════════════════════════════════════════════════╝

Функції:
  • Захоплення пакетів через raw-сокет (Windows promiscuous mode)
  • Виявлення сканування портів (багато портів з одного IP)
  • Виявлення масових запитів (DDoS-паттерн)
  • Виявлення підключень з невідомих IP
  • Сповіщення у реальному часі
  • Логування у файл

Запуск (потрібні права адміністратора):
  python anti_sniffer_cli.py
  python anti_sniffer_cli.py --iface 192.168.1.100
  python anti_sniffer_cli.py --whitelist 192.168.1.0/24
  python anti_sniffer_cli.py --log alerts.log
"""

import socket
import struct
import sys
import time
import threading
import ipaddress
import os
from datetime import datetime
from collections import defaultdict

# ── ANSI-кольори ─────────────────────────────────────────────
class C:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    RED  = "\033[91m"
    GRN  = "\033[92m"
    YLW  = "\033[93m"
    BLU  = "\033[94m"
    MAG  = "\033[95m"
    CYN  = "\033[96m"
    WHT  = "\033[97m"
    BG_RED = "\033[41m"
    BG_YLW = "\033[43m"

# ── Налаштування за замовчуванням ─────────────────────────────
DEFAULTS = {
    "port_scan_threshold": 10,      # портів за вікно → порт-скан
    "port_scan_window": 5,          # секунд
    "mass_req_threshold": 50,       # пакетів за вікно → масовий запит
    "mass_req_window": 3,           # секунд
    "unknown_ip_alert": True,       # сповіщати про невідомі IP
    "whitelist": [],                # дозволені мережі (CIDR)
    "log_file": None,               # файл логу
}

# ── Протоколи ─────────────────────────────────────────────────
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
KNOWN_PORTS = {
    20: "FTP-D", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PgSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def get_local_ip():
    """Визначає локальну IP-адресу."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def parse_ip_header(data):
    """Розбирає IP-заголовок (20+ байт)."""
    if len(data) < 20:
        return None
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = iph[0]
    ihl = (version_ihl & 0xF) * 4
    total_len = iph[2]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return {
        "ihl": ihl, "total_len": total_len,
        "protocol": protocol, "src": src_ip, "dst": dst_ip,
        "payload": data[ihl:]
    }


def parse_tcp_header(data):
    """Розбирає TCP-заголовок."""
    if len(data) < 20:
        return None
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    flags = tcph[5]
    syn = (flags >> 1) & 1
    ack = (flags >> 4) & 1
    fin = flags & 1
    rst = (flags >> 2) & 1
    return {
        "src_port": src_port, "dst_port": dst_port,
        "syn": syn, "ack": ack, "fin": fin, "rst": rst,
        "flags_raw": flags
    }


def parse_udp_header(data):
    """Розбирає UDP-заголовок."""
    if len(data) < 8:
        return None
    udph = struct.unpack("!HHHH", data[:8])
    return {"src_port": udph[0], "dst_port": udph[1], "length": udph[2]}


class AntiSniffer:
    """Основний клас анти-сніфера."""

    def __init__(self, iface=None, whitelist=None, log_file=None,
                 ps_threshold=10, ps_window=5,
                 mr_threshold=50, mr_window=3):
        self.local_ip = iface or get_local_ip()
        self.whitelist_nets = []
        if whitelist:
            for net in whitelist:
                try:
                    self.whitelist_nets.append(ipaddress.ip_network(net, strict=False))
                except ValueError:
                    pass
        # автоматично додаємо локальну мережу
        self.whitelist_nets.append(
            ipaddress.ip_network(self.local_ip + "/24", strict=False))
        self.whitelist_nets.append(
            ipaddress.ip_network("127.0.0.0/8", strict=False))

        self.log_file = log_file
        self.ps_threshold = ps_threshold
        self.ps_window = ps_window
        self.mr_threshold = mr_threshold
        self.mr_window = mr_window

        # статистика
        self.total_packets = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.alerts = []
        self.alert_count = 0

        # трекери
        self.port_tracker = defaultdict(list)   # ip → [(port, time)]
        self.req_tracker = defaultdict(list)     # ip → [time]
        self.seen_ips = set()
        self.alerted_scans = set()
        self.alerted_mass = set()

        self.running = False
        self.start_time = None
        self._lock = threading.Lock()

    def is_whitelisted(self, ip):
        """Перевіряє, чи IP у білому списку."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.whitelist_nets)
        except ValueError:
            return False

    def log_alert(self, level, msg, src_ip="", details=""):
        """Записує сповіщення."""
        ts = datetime.now().strftime("%H:%M:%S")
        alert = {"time": ts, "level": level, "msg": msg,
                 "src": src_ip, "details": details}
        with self._lock:
            self.alerts.append(alert)
            self.alert_count += 1

        # вивід у термінал
        if level == "CRIT":
            icon = f"{C.BG_RED}{C.WHT} ‼ КРИТИЧНО {C.RST}"
            color = C.RED
        elif level == "WARN":
            icon = f"{C.BG_YLW}{C.BOLD} ⚠ УВАГА {C.RST}"
            color = C.YLW
        else:
            icon = f"{C.BLU}ℹ INFO{C.RST}"
            color = C.CYN

        print(f"\n{icon} {color}{C.BOLD}{msg}{C.RST}")
        if src_ip:
            print(f"  {C.DIM}IP:{C.RST} {C.WHT}{src_ip}{C.RST}")
        if details:
            print(f"  {C.DIM}{details}{C.RST}")
        print()

        # запис у файл
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] [{level}] {msg} | IP: {src_ip} | {details}\n")
            except Exception:
                pass

    def check_port_scan(self, src_ip, dst_port):
        """Виявляє сканування портів."""
        now = time.time()
        self.port_tracker[src_ip].append((dst_port, now))
        # очищення старих записів
        self.port_tracker[src_ip] = [
            (p, t) for p, t in self.port_tracker[src_ip]
            if now - t < self.ps_window
        ]
        unique_ports = set(p for p, _ in self.port_tracker[src_ip])
        if len(unique_ports) >= self.ps_threshold:
            key = (src_ip, int(now // self.ps_window))
            if key not in self.alerted_scans:
                self.alerted_scans.add(key)
                ports_list = sorted(unique_ports)[:15]
                ports_str = ", ".join(str(p) for p in ports_list)
                if len(unique_ports) > 15:
                    ports_str += f" ... (+{len(unique_ports)-15})"
                self.log_alert(
                    "CRIT",
                    f"Виявлено сканування портів!",
                    src_ip,
                    f"Портів за {self.ps_window}с: {len(unique_ports)} → {ports_str}"
                )

    def check_mass_requests(self, src_ip):
        """Виявляє масові запити (DDoS-паттерн)."""
        now = time.time()
        self.req_tracker[src_ip].append(now)
        self.req_tracker[src_ip] = [
            t for t in self.req_tracker[src_ip]
            if now - t < self.mr_window
        ]
        count = len(self.req_tracker[src_ip])
        if count >= self.mr_threshold:
            key = (src_ip, int(now // self.mr_window))
            if key not in self.alerted_mass:
                self.alerted_mass.add(key)
                self.log_alert(
                    "CRIT",
                    f"Масові запити (можливий DDoS)!",
                    src_ip,
                    f"Пакетів за {self.mr_window}с: {count}"
                )

    def check_unknown_ip(self, src_ip):
        """Сповіщає про нові невідомі IP."""
        if src_ip not in self.seen_ips:
            self.seen_ips.add(src_ip)
            if not self.is_whitelisted(src_ip):
                self.log_alert(
                    "WARN",
                    f"Підключення з невідомого IP",
                    src_ip,
                    "IP не належить до білого списку"
                )

    def process_packet(self, data):
        """Обробка захопленого пакету."""
        ip = parse_ip_header(data)
        if not ip:
            return
        self.total_packets += 1
        proto = ip["protocol"]
        src = ip["src"]
        dst = ip["dst"]

        # підрахунок за протоколами
        if proto == 6:
            self.tcp_count += 1
            tcp = parse_tcp_header(ip["payload"])
            if tcp:
                dst_port = tcp["dst_port"]
                src_port = tcp["src_port"]
                # перевірки для вхідного трафіку
                if dst == self.local_ip:
                    self.check_port_scan(src, dst_port)
                    self.check_mass_requests(src)
                    self.check_unknown_ip(src)
                # перевірки для вихідного
                elif src == self.local_ip:
                    self.check_port_scan(dst, dst_port)
        elif proto == 17:
            self.udp_count += 1
            udp = parse_udp_header(ip["payload"])
            if udp and dst == self.local_ip:
                self.check_mass_requests(src)
                self.check_unknown_ip(src)
        elif proto == 1:
            self.icmp_count += 1
            if dst == self.local_ip:
                self.check_mass_requests(src)
                self.check_unknown_ip(src)

    def print_packet_line(self, data):
        """Виводить рядок про пакет у реальному часі."""
        ip = parse_ip_header(data)
        if not ip:
            return
        proto = ip["protocol"]
        proto_name = PROTOCOLS.get(proto, str(proto))
        src = ip["src"]
        dst = ip["dst"]

        if proto == 6:
            tcp = parse_tcp_header(ip["payload"])
            if tcp:
                port = tcp["dst_port"]
                svc = KNOWN_PORTS.get(port, "")
                flags = []
                if tcp["syn"]: flags.append("SYN")
                if tcp["ack"]: flags.append("ACK")
                if tcp["fin"]: flags.append("FIN")
                if tcp["rst"]: flags.append("RST")
                flag_str = ",".join(flags) if flags else "---"
                direction = "→" if src == self.local_ip else "←"
                color = C.GRN if src == self.local_ip else C.CYN
                svc_str = f" ({svc})" if svc else ""
                print(
                    f"  {C.DIM}{datetime.now().strftime('%H:%M:%S')}{C.RST} "
                    f"{color}{direction}{C.RST} "
                    f"{proto_name:4} {src:>15}:{tcp['src_port']:<5} → "
                    f"{dst:>15}:{port:<5}{svc_str} "
                    f"[{C.YLW}{flag_str}{C.RST}]",
                    end="\r\n"
                )
        elif proto == 17:
            udp = parse_udp_header(ip["payload"])
            if udp:
                direction = "→" if src == self.local_ip else "←"
                color = C.GRN if src == self.local_ip else C.CYN
                svc = KNOWN_PORTS.get(udp["dst_port"], "")
                svc_str = f" ({svc})" if svc else ""
                print(
                    f"  {C.DIM}{datetime.now().strftime('%H:%M:%S')}{C.RST} "
                    f"{color}{direction}{C.RST} "
                    f"{proto_name:4} {src:>15}:{udp['src_port']:<5} → "
                    f"{dst:>15}:{udp['dst_port']:<5}{svc_str}",
                    end="\r\n"
                )
        elif proto == 1:
            direction = "→" if src == self.local_ip else "←"
            color = C.GRN if src == self.local_ip else C.MAG
            print(
                f"  {C.DIM}{datetime.now().strftime('%H:%M:%S')}{C.RST} "
                f"{color}{direction}{C.RST} "
                f"{proto_name:4} {src:>15}       → {dst:>15}",
                end="\r\n"
            )

    def print_stats(self):
        """Виводить статистику кожні 10 секунд."""
        while self.running:
            time.sleep(10)
            if not self.running:
                break
            elapsed = time.time() - self.start_time
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            print(
                f"\n{C.BLU}{'─'*60}{C.RST}\n"
                f"  {C.BOLD}Статистика{C.RST} ({mins}хв {secs}с) │ "
                f"Пакетів: {C.WHT}{self.total_packets}{C.RST} │ "
                f"TCP: {C.CYN}{self.tcp_count}{C.RST} │ "
                f"UDP: {C.GRN}{self.udp_count}{C.RST} │ "
                f"ICMP: {C.MAG}{self.icmp_count}{C.RST} │ "
                f"Сповіщень: {C.RED}{self.alert_count}{C.RST} │ "
                f"Унікальних IP: {C.YLW}{len(self.seen_ips)}{C.RST}\n"
                f"{C.BLU}{'─'*60}{C.RST}\n"
            )

    def start(self, verbose=True):
        """Запускає захоплення пакетів."""
        print(f"\n{C.BLU}{'═'*60}{C.RST}")
        print(f"  {C.BOLD}{C.CYN}Anti-Sniffer v5{C.RST} — Система виявлення загроз")
        print(f"  {C.DIM}Організація комп. мереж · Нагорний Ілля · РПЗ-24Б{C.RST}")
        print(f"{C.BLU}{'═'*60}{C.RST}\n")

        print(f"  {C.BOLD}Інтерфейс:{C.RST}    {C.WHT}{self.local_ip}{C.RST}")
        print(f"  {C.BOLD}Білий список:{C.RST}  {C.GRN}{', '.join(str(n) for n in self.whitelist_nets)}{C.RST}")
        print(f"  {C.BOLD}Порт-скан:{C.RST}     >{self.ps_threshold} портів за {self.ps_window}с")
        print(f"  {C.BOLD}Масові запити:{C.RST}  >{self.mr_threshold} пакетів за {self.mr_window}с")
        if self.log_file:
            print(f"  {C.BOLD}Лог-файл:{C.RST}     {C.YLW}{self.log_file}{C.RST}")
        print(f"\n  {C.GRN}▶ Моніторинг запущено...{C.RST}  (Ctrl+C — зупинити)\n")
        print(f"  {C.DIM}{'Час':8} {'':2} {'Прот':4} {'Джерело':>15}:{'Порт':<5}   "
              f"{'Призначення':>15}:{'Порт':<5}{C.RST}")
        print(f"  {C.DIM}{'─'*70}{C.RST}")

        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((self.local_ip, 0))
            # включаємо IP-заголовки
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # promiscuous mode (Windows)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except PermissionError:
            print(f"\n  {C.RED}✘ Потрібні права адміністратора!{C.RST}")
            print(f"  {C.DIM}Запустіть: powershell -Command \"Start-Process python "
                  f"-ArgumentList 'anti_sniffer_cli.py' -Verb RunAs\"{C.RST}\n")
            return
        except OSError as e:
            print(f"\n  {C.RED}✘ Помилка сокету: {e}{C.RST}")
            print(f"  {C.DIM}Переконайтесь, що запущено від імені адміністратора.{C.RST}\n")
            return

        self.running = True
        self.start_time = time.time()

        # потік статистики
        stats_thread = threading.Thread(target=self.print_stats, daemon=True)
        stats_thread.start()

        try:
            while self.running:
                try:
                    data, addr = sniffer.recvfrom(65535)
                    self.process_packet(data)
                    if verbose:
                        self.print_packet_line(data)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()
            except Exception:
                pass
            self.print_summary()

    def print_summary(self):
        """Підсумок після зупинки."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        print(f"\n{C.BLU}{'═'*60}{C.RST}")
        print(f"  {C.BOLD}Підсумок моніторингу{C.RST} ({mins}хв {secs}с)")
        print(f"{C.BLU}{'═'*60}{C.RST}")
        print(f"  Пакетів захоплено:   {C.WHT}{self.total_packets}{C.RST}")
        print(f"  TCP:                 {C.CYN}{self.tcp_count}{C.RST}")
        print(f"  UDP:                 {C.GRN}{self.udp_count}{C.RST}")
        print(f"  ICMP:                {C.MAG}{self.icmp_count}{C.RST}")
        print(f"  Унікальних IP:       {C.YLW}{len(self.seen_ips)}{C.RST}")
        print(f"  Сповіщень:           {C.RED}{self.alert_count}{C.RST}")

        if self.alerts:
            print(f"\n  {C.BOLD}Останні сповіщення:{C.RST}")
            for a in self.alerts[-5:]:
                lvl_color = C.RED if a["level"] == "CRIT" else C.YLW
                print(f"    {C.DIM}{a['time']}{C.RST} "
                      f"{lvl_color}[{a['level']}]{C.RST} {a['msg']} "
                      f"({a['src']})")

        if self.log_file and self.alerts:
            print(f"\n  {C.GRN}Лог збережено → {self.log_file}{C.RST}")
        print(f"{C.BLU}{'═'*60}{C.RST}\n")


def parse_args(argv):
    """Розбір аргументів командного рядка."""
    cfg = {
        "iface": None,
        "whitelist": [],
        "log": None,
        "ps_threshold": DEFAULTS["port_scan_threshold"],
        "ps_window": DEFAULTS["port_scan_window"],
        "mr_threshold": DEFAULTS["mass_req_threshold"],
        "mr_window": DEFAULTS["mass_req_window"],
        "quiet": False,
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--iface", "-i") and i + 1 < len(argv):
            cfg["iface"] = argv[i + 1]; i += 2
        elif a in ("--whitelist", "-w") and i + 1 < len(argv):
            cfg["whitelist"] = argv[i + 1].split(","); i += 2
        elif a in ("--log", "-l") and i + 1 < len(argv):
            cfg["log"] = argv[i + 1]; i += 2
        elif a == "--ps-threshold" and i + 1 < len(argv):
            cfg["ps_threshold"] = int(argv[i + 1]); i += 2
        elif a == "--ps-window" and i + 1 < len(argv):
            cfg["ps_window"] = int(argv[i + 1]); i += 2
        elif a == "--mr-threshold" and i + 1 < len(argv):
            cfg["mr_threshold"] = int(argv[i + 1]); i += 2
        elif a == "--mr-window" and i + 1 < len(argv):
            cfg["mr_window"] = int(argv[i + 1]); i += 2
        elif a in ("--quiet", "-q"):
            cfg["quiet"] = True; i += 1
        elif a in ("--help", "-h"):
            print(__doc__)
            sys.exit(0)
        else:
            i += 1
    return cfg


if __name__ == "__main__":
    # Windows: увімкнути ANSI-послідовності
    if sys.platform == "win32":
        os.system("")
    cfg = parse_args(sys.argv[1:])
    sniffer = AntiSniffer(
        iface=cfg["iface"],
        whitelist=cfg["whitelist"],
        log_file=cfg["log"],
        ps_threshold=cfg["ps_threshold"],
        ps_window=cfg["ps_window"],
        mr_threshold=cfg["mr_threshold"],
        mr_window=cfg["mr_window"],
    )
    sniffer.start(verbose=not cfg["quiet"])
