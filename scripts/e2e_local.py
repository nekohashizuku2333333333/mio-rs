#!/usr/bin/env python3
"""Local end-to-end smoke test for mio-rs.

Requires `openssl` on PATH and a debug build at target/debug/mio.
The test uses TCP SOCKS5 and the QUIC warm-up path; it generates a throwaway
self-signed certificate for the camouflage destination.
"""

import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "debug" / "mio"
TLS_PORT = 19445
ECHO_PORT = 19446
SERVER_PORT = 19447
SOCKS_PORT = 19448


def wait_port(port: int, timeout: float = 6.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def tls_server(listener: socket.socket, cert: str, key: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return

        def handle(raw: socket.socket) -> None:
            try:
                stream = context.wrap_socket(raw, server_side=True)
                while stream.recv(65536):
                    pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                raw.close()

        threading.Thread(target=handle, args=(connection,), daemon=True).start()


def echo_server(listener: socket.socket) -> None:
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return

        def handle(stream: socket.socket) -> None:
            try:
                while True:
                    data = stream.recv(65536)
                    if not data:
                        return
                    stream.sendall(data)
            finally:
                stream.close()

        threading.Thread(target=handle, args=(connection,), daemon=True).start()


def main() -> None:
    if not BINARY.exists():
        raise SystemExit(f"missing {BINARY}; run `cargo build` first")
    if shutil.which("openssl") is None:
        raise SystemExit("openssl is required")

    work = Path(tempfile.mkdtemp(prefix="mio-rs-e2e-"))
    cert = work / "cert.pem"
    key = work / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-days",
            "1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key_output = subprocess.check_output([str(BINARY), "keygen"], text=True).splitlines()
    private_key = key_output[0].split(": ", 1)[1]
    public_key = key_output[1].split(": ", 1)[1]
    (work / "server.toml").write_text(
        f"""[log]\nlevel = "debug"\n\n[inbounds]\nlisten = "127.0.0.1"\nlisten_port = {SERVER_PORT}\ndest = "localhost"\ndest_port = {TLS_PORT}\nprivate_key = "{private_key}"\n"""
    )
    (work / "client.toml").write_text(
        f"""[log]\nlevel = "debug"\n\n[outbounds]\nsocks_listen = "127.0.0.1"\nsocks_listen_port = {SOCKS_PORT}\nserver = "127.0.0.1"\nserver_port = {SERVER_PORT}\ndest = "localhost"\ndest_port = {TLS_PORT}\npublic_key = "{public_key}"\ninsecure = true\n"""
    )

    tls_listener = socket.socket()
    tls_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tls_listener.bind(("127.0.0.1", TLS_PORT))
    tls_listener.listen()
    echo_listener = socket.socket()
    echo_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo_listener.bind(("127.0.0.1", ECHO_PORT))
    echo_listener.listen()
    threading.Thread(target=tls_server, args=(tls_listener, str(cert), str(key)), daemon=True).start()
    threading.Thread(target=echo_server, args=(echo_listener,), daemon=True).start()

    log = open(work / "process.log", "wb")
    processes = [
        subprocess.Popen(
            [str(BINARY), "run", "-c", str(work / "server.toml")],
            stdout=log,
            stderr=log,
        ),
        subprocess.Popen(
            [str(BINARY), "run", "-c", str(work / "client.toml")],
            stdout=log,
            stderr=log,
        ),
    ]
    try:
        assert wait_port(TLS_PORT), "TLS destination failed"
        assert wait_port(SERVER_PORT), "mio server failed"
        assert wait_port(SOCKS_PORT), "mio client failed"
        time.sleep(1.2)  # let the QUIC warm-up establish

        stream = socket.create_connection(("127.0.0.1", SOCKS_PORT), 3)
        stream.settimeout(10)
        stream.sendall(b"\x05\x01\x00")
        assert stream.recv(2) == b"\x05\x00"
        host = b"127.0.0.1"
        stream.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host)])
            + host
            + ECHO_PORT.to_bytes(2, "big")
        )
        reply = stream.recv(10)
        assert reply[:2] == b"\x05\x00", reply.hex()
        payload = b"mio-rs e2e over TCP/QUIC fallback\n" * 100
        stream.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = stream.recv(65536)
            if not chunk:
                break
            received += chunk
        assert received == payload, (len(received), len(payload))

        # A second SOCKS request should reuse the same authenticated TCP/QUIC
        # session instead of requiring a new outer connection.
        second = socket.create_connection(("127.0.0.1", SOCKS_PORT), 3)
        second.settimeout(10)
        second.sendall(b"\x05\x01\x00")
        assert second.recv(2) == b"\x05\x00"
        second.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host)])
            + host
            + ECHO_PORT.to_bytes(2, "big")
        )
        reply = second.recv(10)
        assert reply[:2] == b"\x05\x00", reply.hex()
        second_payload = b"mio-rs multiplexed session\n" * 100
        second.sendall(second_payload)
        second_received = b""
        while len(second_received) < len(second_payload):
            chunk = second.recv(65536)
            if not chunk:
                break
            second_received += chunk
        assert second_received == second_payload, (
            len(second_received),
            len(second_payload),
        )
        second.close()
        print("E2E PASS: SOCKS5 -> mio -> echo (two requests)")
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        log.close()
        tls_listener.close()
        echo_listener.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()