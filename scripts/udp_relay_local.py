#!/usr/bin/env python3
"""Verify unmarked UDP traffic is relayed to the camouflage destination."""

import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "debug" / "mio"
SERVER_PORT = 19851
DEST_PORT = 19850


def udp_echo(sock: socket.socket) -> None:
    while True:
        try:
            payload, address = sock.recvfrom(65535)
            sock.sendto(payload, address)
        except OSError:
            return


def main() -> None:
    if not BINARY.exists():
        raise SystemExit(f"missing {BINARY}; run `cargo build` first")
    work = Path(tempfile.mkdtemp(prefix="mio-rs-udp-"))
    keys = subprocess.check_output([str(BINARY), "keygen"], text=True).splitlines()
    private_key = keys[0].split(": ", 1)[1]
    config = work / "server.toml"
    config.write_text(
        f"""[log]\nlevel = "debug"\n\n[inbounds]\nlisten = "127.0.0.1"\nlisten_port = {SERVER_PORT}\ndest = "127.0.0.1"\ndest_port = {DEST_PORT}\nprivate_key = "{private_key}"\n"""
    )

    destination = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    destination.bind(("127.0.0.1", DEST_PORT))
    threading.Thread(target=udp_echo, args=(destination,), daemon=True).start()
    log = open(work / "process.log", "wb")
    process = subprocess.Popen(
        [str(BINARY), "run", "-c", str(config)], stdout=log, stderr=log
    )
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        time.sleep(0.7)
        client.bind(("127.0.0.1", 0))
        client.settimeout(4)
        payload = b"unmarked UDP must be relayed to the camouflage destination"
        client.sendto(payload, ("127.0.0.1", SERVER_PORT))
        response, address = client.recvfrom(65535)
        assert response == payload, (len(response), len(payload))
        print(f"UDP RELAY PASS: {address} -> camouflage destination")
    finally:
        process.terminate()
        process.wait(timeout=3)
        log.close()
        client.close()
        destination.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()