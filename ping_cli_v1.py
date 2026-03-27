"""
ping_cli.py — утиліта пінгування у стилі cisco packet tracer
використовує бібліотеку subprocess для виклику системної команди ping
"""

import subprocess
import re
import sys
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


def ping(host, count=4):
    """
    пінгує хост і виводить кожну відповідь одразу при отриманні

    аргументи:
        host  — ip-адреса або доменне ім'я
        count — кількість пакетів (за замовчуванням 4)
    """
    system = platform.system().lower()

    # на windows форсуємо англійський вивід через chcp 437, щоб уникнути проблем з кодуванням
    if system == "windows":
        cmd = f"chcp 437 > nul & ping -n {count} {host}"
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="ascii",
            errors="replace",
            shell=True
        )
    else:
        process = subprocess.Popen(
            ["ping", "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

    print(f"\nPinging {host} with 32 bytes of data:\n")

    times = []
    received = 0

    # читаємо вивід рядок за рядком — кожна відповідь виводиться одразу
    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if not line:
            continue

        ll = line.lower()

        if "reply from" in ll:
            received += 1
            t, time_str = parse_time(line)
            times.append(t)
            print(f"Reply from {host}: bytes=32 {time_str} TTL=128")

        elif "request timed out" in ll:
            print("Request timed out.")

        elif "destination host unreachable" in ll:
            print(f"Reply from {host}: Destination host unreachable.")

    process.wait()

    lost = count - received
    loss_pct = int((lost / count) * 100)

    print(f"\nPing statistics for {host}:")
    print(f"    Packets: Sent = {count}, Received = {received}, Lost = {lost} ({loss_pct}% loss),")

    if times:
        min_t = min(times)
        max_t = max(times)
        avg_t = round(sum(times) / len(times))
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min_t}ms, Maximum = {max_t}ms, Average = {avg_t}ms")
    print()


def main():
    print("Cisco Packet Tracer PC Command Line 1.0")

    if len(sys.argv) >= 2:
        host = sys.argv[1]
        count = int(sys.argv[2]) if len(sys.argv) >= 3 else 4
        print(f"C:\\>ping {host}")
        ping(host, count)
    else:
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

            if parts[0].lower() == "ping":
                if len(parts) < 2:
                    print("Використання: ping <хост> [-n <кількість>]")
                    continue

                host = None
                count = 4

                i = 1
                while i < len(parts):
                    if parts[i] == "-n" and i + 1 < len(parts):
                        count = int(parts[i + 1])
                        i += 2
                    else:
                        host = parts[i]
                        i += 1

                if host:
                    ping(host, count)
                else:
                    print("Використання: ping <хост> [-n <кількість>]")

            elif parts[0].lower() in ("exit", "quit"):
                break
            else:
                print(f"'{parts[0]}' не є внутрішньою або зовнішньою командою.")


if __name__ == "__main__":
    main()
