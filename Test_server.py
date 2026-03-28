import socket
import ssl
import threading
import subprocess
import os
import time

CERT_FILE = "server.crt"
KEY_FILE  = "server.key"

# each service: (port, banner, use_ssl, name)
SERVICES = [
    (9000, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n",         False, "HTTP-Sim"),
    (9001, b"SSH-2.0-OpenSSH_9.3 Ubuntu\r\n",                         False, "SSH-Sim"),
    (9002, b"220 FTP Server ready\r\n",                                False, "FTP-Sim"),
    (9003, b"220 SMTP Server ready\r\n",                               False, "SMTP-Sim"),
    (9004, b"+OK POP3 ready\r\n",                                      False, "POP3-Sim"),
    (9443, b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n",          True,  "HTTPS-Sim"),
]

# ports that simulate error conditions: (port, error_banner, name)
ERROR_SERVICES = [
    (9005, b"HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4\r\nContent-Length: 0\r\n\r\n",     "403-Forbidden"),
    (9006, b"HTTP/1.1 503 Service Unavailable\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n", "503-Unavailable"),
    (9007, b"SSH-2.0-OpenSSH_9.3\r\nERROR: Too many connections. Try again later.\r\n",       "SSH-Overloaded"),
    (9008, b"550 Access denied - your IP is blacklisted\r\n",                                  "SMTP-Rejected"),
]


def make_certificate():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("[SSL] certificate already exists")
        return True

    print("[SSL] generating self-signed certificate...")
    result = subprocess.run([
        "openssl", "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", KEY_FILE,
        "-out",    CERT_FILE,
        "-days",   "365",
        "-nodes",
        "-subj",   "/CN=localhost/O=Lab/C=IN"
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print("[SSL] certificate ready")
        return True
    else:
        print("[SSL] failed:", result.stderr)
        return False


def make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


def handle_client(conn, addr, port, banner, name):
    peer = f"{addr[0]}:{addr[1]}"
    try:
        conn.settimeout(2.0)

        # read whatever the scanner sends first
        try:
            data = conn.recv(256)
            if data:
                # check if it's binary (SSL handshake) or readable text
                binary_bytes = sum(1 for b in data if b < 0x20 and b not in (9, 10, 13))
                if binary_bytes > 4:
                    print(f"  [{name}] SSL probe from {peer} (ignored)")
                else:
                    print(f"  [{name}] probe from {peer}: {data.decode(errors='replace').strip()[:50]!r}")
        except socket.timeout:
            pass  # scanner didn't send anything, that's fine

        # send the banner back
        conn.sendall(banner)
        print(f"  [{name}] banner sent to {peer}")

    except (ConnectionResetError, BrokenPipeError):
        print(f"  [{name}] {peer} disconnected")
    except ssl.SSLError as e:
        print(f"  [{name}] SSL error: {e}")
    except Exception as e:
        print(f"  [{name}] error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass


def run_service(port, banner, use_ssl, name, ssl_ctx):
    # create the server socket manually (no frameworks)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"  [!] cannot bind port {port}: {e}")
        return

    server.listen(10)
    tag = " [TLS]" if use_ssl else ""
    print(f"  listening on port {port}{tag}  ({name})")

    while True:
        try:
            conn, addr = server.accept()

            # wrap in SSL if this service needs it
            if use_ssl and ssl_ctx:
                try:
                    conn = ssl_ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError as e:
                    print(f"  [!] SSL handshake failed from {addr[0]}: {e}")
                    conn.close()
                    continue

            # each client gets its own thread
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, port, banner, name),
                daemon=True
            )
            t.start()

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  [!] accept error on port {port}: {e}")


def handle_error_client(conn, addr, error_banner, name):
    """Accept connection, send an error banner, then close — simulates a live but rejecting service."""
    peer = f"{addr[0]}:{addr[1]}"
    try:
        conn.settimeout(2.0)
        try:
            data = conn.recv(256)
            if data:
                print(f"  [{name}] probe from {peer}: {data.decode(errors='replace').strip()[:50]!r}")
        except socket.timeout:
            pass
        conn.sendall(error_banner)
        print(f"  [{name}] error banner sent to {peer}")
    except (ConnectionResetError, BrokenPipeError):
        print(f"  [{name}] {peer} disconnected")
    except Exception as e:
        print(f"  [{name}] error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass


def run_error_service(port, error_banner, name):
    """A service that is reachable but always responds with an error."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"  [!] cannot bind port {port}: {e}")
        return
    server.listen(10)
    print(f"  listening on port {port}  ({name}) [ERROR-SIM]")
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_error_client,
                args=(conn, addr, error_banner, name),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  [!] accept error on port {port}: {e}")


def main():
    print("\n  Multi-Service Test Server")
    print("-" * 40)

    ssl_ctx = None
    if make_certificate():
        try:
            ssl_ctx = make_ssl_context()
            print("[SSL] context ready\n")
        except Exception as e:
            print(f"[SSL] context failed: {e}\n")

    for port, banner, use_ssl, name in SERVICES:
        if use_ssl and ssl_ctx is None:
            print(f"  skipping port {port} — no SSL context")
            continue
        ctx = ssl_ctx if use_ssl else None
        t = threading.Thread(
            target=run_service,
            args=(port, banner, use_ssl, name, ctx),
            daemon=True
        )
        t.start()

    for port, error_banner, name in ERROR_SERVICES:
        t = threading.Thread(
            target=run_error_service,
            args=(port, error_banner, name),
            daemon=True
        )
        t.start()

    print("\n  All services running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopped.")


main()