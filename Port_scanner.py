import socket
import ssl
import select
import threading
import time
from queue import Queue


# ---------- settings ----------
target      = input("Enter target IP: ").strip()
start_port  = 9000
end_port    = 9500
num_threads = 200
timeout     = 1.0
max_retries = 1
# ------------------------------

print_lock = threading.Lock()
port_queue = Queue()
open_count = closed_count = filtered_count = error_count = 0
count_lock = threading.Lock()
open_ports  = []   # list of (port, display_name, banner)
error_ports = []   # list of (port, display_name, banner)

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 8080: "HTTP-Alt",
    9000: "HTTP-Sim",  9001: "SSH-Sim",   9002: "FTP-Sim",
    9003: "SMTP-Sim",  9004: "POP3-Sim",  9443: "HTTPS-Sim",
    9005: "HTTP-Sim",  9006: "HTTP-Sim",
    9007: "SSH-Sim",   9008: "SMTP-Sim",
}

DISPLAY_NAMES = {
    9005: "403-Forbidden",   9006: "503-Unavailable",
    9007: "SSH-Overloaded",  9008: "SMTP-Rejected",
}

ERROR_SIGNATURES = [
    "403", "503", "550", "530", "421",
    "denied", "blacklisted", "forbidden",
    "unavailable", "overloaded", "too many",
    "error", "rejected"
]

SSL_ONLY_PORTS = {443, 465, 993, 995, 8443, 9443}

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
RESET  = "\033[0m"


def get_service(port):
    return SERVICES.get(port, "Unknown")

def get_display_name(port):
    return DISPLAY_NAMES.get(port, get_service(port))

def grab_banner(sock, service):
    try:
        if "HTTP" in service:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif "SMTP" in service:
            sock.sendall(b"EHLO scanner\r\n")
        elif "IMAP" in service:
            sock.sendall(b"A1 CAPABILITY\r\n")
        elif "SSH" in service:
            # send a dummy probe so the test server sends its banner back
            sock.sendall(b"SSH-2.0-Scanner\r\n")
        else:
            # for unknown services, send a generic probe to trigger a response
            sock.sendall(b"\r\n")
        sock.settimeout(timeout)
        return sock.recv(1024).decode(errors="ignore").strip()[:200]
    except:
        return ""

def check_ssl(port, service):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((target, port), timeout=3.0)
        wrapped = ctx.wrap_socket(raw, server_hostname=target)
        version = wrapped.version()
        try:
            wrapped.unwrap()
        except:
            pass
        wrapped.close()
        return True, version
    except:
        return False, ""

def is_error_banner(banner):
    return any(sig in banner.lower() for sig in ERROR_SIGNATURES)

def log(status, port, service, elapsed, detail="", retry_note=""):
    if   status == "OPEN":            colour, label = GREEN,  "[ OPEN     ]"
    elif status == "ERROR":           colour, label = RED,    "[ ERROR    ]"
    elif status == "CLOSED/FILTERED": colour, label = GREY,   "[ closed   ]"
    elif status == "SSL-OPEN":        colour, label = CYAN,   "[ SSL OPEN ]"
    else:                             colour, label = YELLOW, "[ FILTERED ]"

    detail_str = f"  ->  {detail}" if detail else ""
    retry_str  = f"  (retried {retry_note}x)" if retry_note else ""
    line = (
        f"  {colour}{label}{RESET} "
        f"port {port:<6} | "
        f"service: {service:<16} | "
        f"{elapsed:>7}s"
        f"{detail_str}{retry_str}"
    )
    with print_lock:
        print(line)


def tcp_connect(port):
    """
    Blocking connect with timeout.
    Returns: ("open", sock) | ("closed_or_filtered", None)
    On Windows, both closed and filtered ports return 10035 —
    there is no socket-level way to distinguish them.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        return "open", sock
    except ConnectionRefusedError:
        sock.close()
        return "closed_or_filtered", None
    except OSError:
        # covers 10035 (Windows WSAEWOULDBLOCK/timeout) and ETIMEDOUT
        sock.close()
        return "closed_or_filtered", None


def scan_port(port):
    global open_count, closed_count, filtered_count, error_count

    service      = get_service(port)
    display_name = get_display_name(port)
    t_start      = time.perf_counter()

    # SSL-only ports
    if port in SSL_ONLY_PORTS:
        ssl_ok, version = check_ssl(port, service)
        elapsed = round(time.perf_counter() - t_start, 4)
        with count_lock:
            if ssl_ok:
                open_count += 1
                open_ports.append((port, display_name, f"SSL {version}  |  TLS handshake OK"))
            else:
                closed_count += 1
        if ssl_ok:
            log("SSL-OPEN", port, display_name, elapsed,
                detail=f"TLS handshake OK  |  version: {version}")
        else:
            log("CLOSED/FILTERED", port, display_name, elapsed,
                detail="SSL connection failed")
        return

    # plain TCP ports
    retries = 0
    for attempt in range(max_retries + 1):

        state, sock = tcp_connect(port)
        elapsed = round(time.perf_counter() - t_start, 4)

        if state == "open":
            banner     = grab_banner(sock, service)
            retry_note = str(retries) if retries > 0 else ""
            sock.close()
            if is_error_banner(banner):
                with count_lock:
                    error_count += 1
                    error_ports.append((port, display_name, banner))
                log("ERROR", port, display_name, elapsed,
                    detail=f"service replied with error  |  banner: \"{banner}\"",
                    retry_note=retry_note)
            else:
                with count_lock:
                    open_count += 1
                    open_ports.append((port, display_name, banner))
                banner_str = f"banner: \"{banner}\"" if banner else "no banner received"
                log("OPEN", port, display_name, elapsed,
                    detail=banner_str, retry_note=retry_note)
            return

        else:
            # on Windows, no way to distinguish closed from filtered
            # retry once in case of transient issue, then mark as closed/filtered
            retries += 1
            if attempt < max_retries:
                continue
            with count_lock:
                closed_count += 1
            log("CLOSED/FILTERED", port, display_name, elapsed,
                detail="no response  |  nothing listening or port is firewalled")
            return


def worker():
    while True:
        port = port_queue.get()
        if port is None:
            break
        scan_port(port)
        port_queue.task_done()

def print_port_distribution():
    total = open_count + closed_count + error_count

    if total == 0:
        return

    print("\n" + "=" * 75)
    print("  PORT DISTRIBUTION")
    print("=" * 75)

    categories = [
        ("Open", open_count, GREEN),
        ("Closed / Filtered", closed_count, GREY),
        ("Error / Rejected", error_count, RED),
    ]

    max_bar_width = 40

    for label, value, colour in categories:
        percent = (value / total) * 100
        filled = round((value / total) * max_bar_width)

        if value > 0 and filled == 0:
            filled = 1

        if filled > max_bar_width:
            filled = max_bar_width

        empty = max_bar_width - filled

        filled_bar = "#" * filled
        empty_bar = "-" * empty

        print(
            f"  {label:<20} "
            f"[{colour}{filled_bar}{RESET}{GREY}{empty_bar}{RESET}] "
            f"{value:>4} ports ({percent:>5.1f}%)"
        )
        
def main():
    ports = list(range(start_port, end_port + 1))

    print(f"\n  Target : {target}")
    print(f"  Range  : ports {start_port} - {end_port}  ({len(ports)} ports)")
    print(f"  Threads: {num_threads}   |   Timeout: {timeout}s   |   Max retries: {max_retries}")
    print("=" * 75)
    print(f"  {'STATUS':<13} {'PORT':<8} {'SERVICE':<18} {'TIME':>8}   DETAIL")
    print("=" * 75)

    scan_start = time.perf_counter()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for port in ports:
        port_queue.put(port)

    port_queue.join()

    for _ in range(num_threads):
        port_queue.put(None)
    for t in threads:
        t.join()

    total_time = round(time.perf_counter() - scan_start, 2)

    print("\n" + "=" * 75)
    print("  SCAN SUMMARY")
    print("=" * 75)
    print(f"  Total scanned        : {len(ports)}")

    # Open ports — list each one with service and banner
    print(f"{GREEN}  Open                 : {open_count}{RESET}")
    for port, name, banner in sorted(open_ports):
        usage = banner.split("\r\n")[0][:60] if banner else "no banner"
        print(f"{GREEN}    port {port:<6}  {name:<18}  {usage}{RESET}")

    # Error ports — list each one with reason
    print(f"{RED}  Error / Rejected     : {error_count}   <- port reachable but service sent error{RESET}")
    for port, name, banner in sorted(error_ports):
        reason = banner.split("\r\n")[0][:60] if banner else "unknown error"
        print(f"{RED}    port {port:<6}  {name:<18}  reason: {reason}{RESET}")

    print(f"{GREY}  Closed / Filtered    : {closed_count}   <- no response received{RESET}")
    print(f"\n  Total time           : {total_time}s")
    print(f"  Speed                : {round(len(ports) / total_time, 1)} ports/sec")
    print_port_distribution()
    print("=" * 75)


main()