#!/usr/bin/env python3
"""
TRS Backend Logger
Pure TCP server that records *exactly* what the application receives on the wire.
No HTTP parsing on purpose - we want the raw bytes the real backend would see.
"""

import socket
import sys
import os
import time
import threading
from datetime import datetime, timezone


def hexdump(data: bytes, width: int = 16) -> str:
    """Return a classic hexdump string for the given bytes."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def log(msg: str):
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    print(f"[{ts}] {msg}", flush=True)


def handle_client(conn: socket.socket, addr: tuple):
    conn.settimeout(45.0)
    peer = f"{addr[0]}:{addr[1]}"
    total = bytearray()
    chunks = 0

    log(f"NEW CONNECTION from {peer}")

    try:
        while True:
            try:
                chunk = conn.recv(65535)
            except socket.timeout:
                log(f"TIMEOUT waiting for more data from {peer}")
                break

            if not chunk:
                # FIN or close
                break

            chunks += 1
            total.extend(chunk)
            log(f"RECV {len(chunk)} bytes (chunk #{chunks}) from {peer}")
            # Log the exact bytes in multiple formats for analysis
            log(f"  repr: {chunk!r}")
            if len(chunk) <= 256:
                log("  hexdump:\n" + hexdump(chunk))
            else:
                log("  hexdump (first 256):\n" + hexdump(chunk[:256]))
                log(f"  ... ({len(chunk)-256} more bytes)")

    except Exception as exc:
        log(f"ERROR on {peer}: {exc}")
    finally:
        conn.close()
        log(f"CLOSED {peer} - total received: {len(total)} bytes in {chunks} chunks")
        if total:
            # Final summary — the "application view".
            # Peer is embedded in the markers so analyze.py can correlate
            # even when multiple connections interleave in the log.
            log(f"=== APPLICATION VIEW peer={peer} (exact bytes delivered to app) ===")
            log(hexdump(bytes(total)))
            log(f"=== END peer={peer} len={len(total)} ===")
        else:
            log("No data received on this connection.")


def main():
    bind_host = "0.0.0.0"
    bind_port = int(os.environ.get("BACKEND_PORT", "8080"))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Allow quick reuse even if in TIME_WAIT from previous test
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass

    srv.bind((bind_host, bind_port))
    srv.listen(10)
    log(f"TRS Backend listening on {bind_host}:{bind_port} (TCP)")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Shutting down backend.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()