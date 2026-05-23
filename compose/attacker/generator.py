#!/usr/bin/env python3
"""
TRS Traffic Generator (Phase 1)

Capabilities:
- Baseline: normal delivery, no loss
- Loss-induced retransmission (real kernel retransmits of identical data)
- (Future) Raw socket spurious retransmit / overlapping segments with different content

Uses only stdlib + subprocess for tc/iptables (as required).

Run inside the attacker container (or with proper caps + routes).
"""

import argparse
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone


TARGET_DEFAULT = "10.20.0.2:8080"
IFACE_DEFAULT = "eth0"          # inside the attacker container


def log(msg: str):
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    print(f"[{ts}] [generator] {msg}", flush=True)


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and log it."""
    log(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def setup_loss(iface: str, loss_pct: float, delay_ms: int = 0):
    """Add netem qdisc for loss (and optional delay) on egress."""
    # Remove any existing qdisc first
    run(["tc", "qdisc", "del", "dev", iface, "root"], check=False)
    cmd = ["tc", "qdisc", "add", "dev", iface, "root", "netem"]
    if loss_pct > 0:
        cmd += ["loss", f"{loss_pct}%"]
    if delay_ms > 0:
        cmd += ["delay", f"{delay_ms}ms"]
    run(cmd)


def cleanup_qdisc(iface: str):
    run(["tc", "qdisc", "del", "dev", iface, "root"], check=False)


def send_payload(target: str, payload: bytes, nodelay: bool = True, send_delay: float = 0.0) -> int:
    """
    Establish TCP connection, send payload (optionally in pieces), return bytes sent.
    """
    host, port = target.split(":")
    port = int(port)

    log(f"Connecting to {host}:{port} ...")
    with socket.create_connection((host, port), timeout=30) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if nodelay else 0)

        total = 0
        # For demo we can split into multiple segments if desired by caller
        # Here we send the whole thing in one call (kernel may still segment)
        # To force more segments, the caller can loop with small writes + time.sleep
        if send_delay > 0:
            # Example: send in two parts with a gap to create distinct segments
            mid = len(payload) // 2 or 1
            s.sendall(payload[:mid])
            total += mid
            time.sleep(send_delay)
            s.sendall(payload[mid:])
            total += len(payload) - mid
        else:
            s.sendall(payload)
            total = len(payload)

        log(f"Sent {total} bytes. Waiting for remote close / timeout...")
        # We don't care about the reply for this lab (one-way data test)
        # Just drain or wait a bit so the last segment has time to be ACKed
        s.settimeout(2.0)
        try:
            while s.recv(4096):
                pass
        except socket.timeout:
            pass

    log("Connection closed from our side.")
    return total


def build_test_payload(case: str) -> bytes:
    """Return interesting payloads for different test cases."""
    if case == "baseline" or case == "loss":
        # Simple HTTP-like request that a WAF might inspect
        return (
            b"GET /api/v1/user?id=1' OR '1'='1 HTTP/1.1\r\n"
            b"Host: trs-lab.local\r\n"
            b"User-Agent: TRS-Generator/1.0\r\n"
            b"Accept: */*\r\n"
            b"X-Custom: <script>alert(1)</script>\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
    if case == "overlap":
        # Will be used in raw-injection phase
        return b"OVERLAP_TEST_" + b"A" * 200 + b"B" * 200
    return b"TRS-TEST-PAYLOAD-" + b"X" * 512


def main():
    parser = argparse.ArgumentParser(description="TRS Lab Traffic Generator")
    parser.add_argument("--target", default=TARGET_DEFAULT,
                        help="host:port of the backend (default: 10.20.0.2:8080)")
    parser.add_argument("--iface", default=IFACE_DEFAULT,
                        help="network interface for tc netem (default: eth0)")
    parser.add_argument("--case", choices=["baseline", "loss", "overlap", "spurious"],
                        default="baseline", help="Test scenario to run")
    parser.add_argument("--loss", type=float, default=8.0,
                        help="Packet loss %% for 'loss' case (default 8%%)")
    parser.add_argument("--delay", type=int, default=5,
                        help="Extra delay (ms) for netem in loss case")
    parser.add_argument("--count", type=int, default=1,
                        help="How many connections / iterations to perform")
    parser.add_argument("--send-delay", type=float, default=0.05,
                        help="Delay (seconds) between partial sends to encourage distinct segments")

    args = parser.parse_args()

    log(f"TRS Generator starting - case={args.case} target={args.target}")

    payload = build_test_payload(args.case)
    log(f"Payload length: {len(payload)} bytes")

    for i in range(args.count):
        log(f"=== Run {i+1}/{args.count} ===")

        if args.case == "loss":
            log(f"Applying netem loss={args.loss}% delay={args.delay}ms on {args.iface}")
            setup_loss(args.iface, args.loss, args.delay)
            # Give qdisc a moment
            time.sleep(0.2)

        try:
            sent = send_payload(
                args.target,
                payload,
                nodelay=True,
                send_delay=args.send_delay if args.case in ("loss", "baseline") else 0.0,
            )
            log(f"Run {i+1} completed, sent={sent} bytes")
        finally:
            if args.case == "loss":
                log("Cleaning up netem qdisc")
                cleanup_qdisc(args.iface)
                time.sleep(0.3)

        if i < args.count - 1:
            time.sleep(1.0)

    log("All runs finished. Check /pcaps/ on the middle container and backend logs.")


if __name__ == "__main__":
    main()