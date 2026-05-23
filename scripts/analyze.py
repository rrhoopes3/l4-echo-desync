#!/usr/bin/env python3
"""
TRS Desync Analyzer

Parses:
  - Zeek output from `zeek -r <pcap> /zeek-config/local.zeek` (text events
    emitted by configs/zeek/local.zeek: CONN_EST, TCP_CONTENTS, TCP_REXMIT,
    TCP_WEIRD, CONN_END)
  - Backend container log (the APPLICATION VIEW hexdumps and chunk records)

Correlates Zeek connections with backend connections by orig_port (the
attacker's ephemeral port, which Zeek prints in CONN_EST and the backend
logs in NEW CONNECTION from <ip>:<port>).

For Phase 2 (overlap/partial): now emits clear "content diverges" verdict with
hex samples of Zeek-reassembled vs backend-received bytes and first-diff offset.

Emits one record per matched connection:
  - bytes Zeek's reassembler delivered (C->S direction, from tcp_contents)
  - bytes the backend application received
  - retransmit count, weird events
  - desync verdict + hex evidence when Zeek view != backend bytes

Usage:
    # 1. Run Zeek on the latest right-leg pcap, saving its prints
    docker compose --profile zeek run --rm zeek \\
        zeek -C -r /pcaps/right-XXXXX.pcap /zeek-config/local.zeek \\
        > zeek-run.txt 2>&1

    # 2. Save backend log
    docker compose logs --no-color backend > backend.log

    # 3. Diff them
    python scripts/analyze.py --zeek zeek-run.txt --backend backend.log

Exit code 0 = no desync detected; 2 = desync detected; 1 = parse error.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# === Zeek event regexes ===

RE_CONN_EST = re.compile(
    r"CONN_EST uid=(?P<uid>\S+) "
    r"(?P<orig_ip>[\d.]+):(?P<orig_port>\d+) -> "
    r"(?P<resp_ip>[\d.]+):(?P<resp_port>\d+)"
)
RE_TCP_CONTENTS = re.compile(
    r"TCP_CONTENTS uid=(?P<uid>\S+) (?P<dir>C->S|S->C) "
    r"seq=(?P<seq>\d+) len=(?P<len>\d+) preview=(?P<preview>.*)"
)
RE_TCP_REXMIT = re.compile(
    r"TCP_REXMIT uid=(?P<uid>\S+) (?P<dir>C->S|S->C) "
    r"seq=(?P<seq>\d+) len=(?P<len>\d+)"
)
RE_TCP_WEIRD = re.compile(
    r"TCP_WEIRD uid=(?P<uid>\S+) name=(?P<name>\S+) addl=(?P<addl>.*)"
)
RE_CONN_END = re.compile(
    r"CONN_END uid=(?P<uid>\S+) duration=\S+ "
    r"orig_bytes=(?P<orig_bytes>\d+) resp_bytes=(?P<resp_bytes>\d+)"
)


# === Backend log regexes ===

# [2025-... ] NEW CONNECTION from 10.10.0.2:54321
RE_BACKEND_NEW = re.compile(
    r"NEW CONNECTION from (?P<ip>[\d.]+):(?P<port>\d+)"
)
# [2025-... ] CLOSED 10.10.0.2:54321 - total received: 234 bytes in 3 chunks
RE_BACKEND_CLOSED = re.compile(
    r"CLOSED (?P<ip>[\d.]+):(?P<port>\d+) - total received: (?P<bytes>\d+) bytes in (?P<chunks>\d+) chunks"
)
# Hexdump lines: "0000  47 45 54 ...  GET ..."
# The backend's log() function prefixes the FIRST line of each multi-line
# print with "[<timestamp>] "; subsequent lines are bare. Allow either.
RE_HEXDUMP_LINE = re.compile(
    r"^(?:\[[^\]]+\]\s+)?([0-9a-f]{4})\s+((?:[0-9a-f]{2}\s+){1,16})\s+(.{1,16})\s*$"
)
RE_APP_VIEW_START = re.compile(
    r"=== APPLICATION VIEW peer=(?P<ip>[\d.]+):(?P<port>\d+) "
    r"\(exact bytes delivered to app\) ==="
)
RE_APP_VIEW_END = re.compile(
    r"=== END peer=(?P<ip>[\d.]+):(?P<port>\d+) len=(?P<len>\d+) ==="
)


# === Data classes ===

@dataclass
class ZeekConn:
    uid: str
    orig_ip: str = ""
    orig_port: int = 0
    resp_ip: str = ""
    resp_port: int = 0
    c2s_chunks: list[tuple[int, int, str]] = field(default_factory=list)  # (seq, len, preview)
    s2c_chunks: list[tuple[int, int, str]] = field(default_factory=list)
    rexmits: list[tuple[str, int, int]] = field(default_factory=list)     # (dir, seq, len)
    weirds: list[tuple[str, str]] = field(default_factory=list)           # (name, addl)
    orig_bytes_final: Optional[int] = None
    resp_bytes_final: Optional[int] = None

    @property
    def c2s_total_len(self) -> int:
        return sum(c[1] for c in self.c2s_chunks)

    @property
    def c2s_preview_concat(self) -> str:
        return "".join(c[2] for c in self.c2s_chunks)


@dataclass
class BackendConn:
    orig_ip: str
    orig_port: int
    total_bytes: Optional[int] = None
    app_view_hex: bytes = b""           # reconstructed from hexdump
    app_view_declared_len: Optional[int] = None


# === Parsers ===

def parse_zeek(path: Path) -> dict[str, ZeekConn]:
    conns: dict[str, ZeekConn] = {}

    def get(uid: str) -> ZeekConn:
        if uid not in conns:
            conns[uid] = ZeekConn(uid=uid)
        return conns[uid]

    for line in path.read_text(errors="replace").splitlines():
        m = RE_CONN_EST.search(line)
        if m:
            c = get(m["uid"])
            c.orig_ip = m["orig_ip"]
            c.orig_port = int(m["orig_port"])
            c.resp_ip = m["resp_ip"]
            c.resp_port = int(m["resp_port"])
            continue

        m = RE_TCP_CONTENTS.search(line)
        if m:
            c = get(m["uid"])
            entry = (int(m["seq"]), int(m["len"]), m["preview"])
            if m["dir"] == "C->S":
                c.c2s_chunks.append(entry)
            else:
                c.s2c_chunks.append(entry)
            continue

        m = RE_TCP_REXMIT.search(line)
        if m:
            c = get(m["uid"])
            c.rexmits.append((m["dir"], int(m["seq"]), int(m["len"])))
            continue

        m = RE_TCP_WEIRD.search(line)
        if m:
            c = get(m["uid"])
            c.weirds.append((m["name"], m["addl"]))
            continue

        m = RE_CONN_END.search(line)
        if m:
            c = get(m["uid"])
            c.orig_bytes_final = int(m["orig_bytes"])
            c.resp_bytes_final = int(m["resp_bytes"])
            continue

    return conns


def parse_backend(path: Path) -> dict[tuple[str, int], BackendConn]:
    """Group backend log lines by source IP:port, recover the APPLICATION VIEW bytes."""
    conns: dict[tuple[str, int], BackendConn] = {}
    appview_key: Optional[tuple[str, int]] = None
    appview_buf = bytearray()

    for line in path.read_text(errors="replace").splitlines():
        m = RE_BACKEND_NEW.search(line)
        if m:
            key = (m["ip"], int(m["port"]))
            conns[key] = BackendConn(orig_ip=key[0], orig_port=key[1])
            continue

        m = RE_BACKEND_CLOSED.search(line)
        if m:
            key = (m["ip"], int(m["port"]))
            if key in conns:
                conns[key].total_bytes = int(m["bytes"])
            continue

        m = RE_APP_VIEW_START.search(line)
        if m:
            appview_key = (m["ip"], int(m["port"]))
            appview_buf = bytearray()
            continue

        m = RE_APP_VIEW_END.search(line)
        if m:
            key = (m["ip"], int(m["port"]))
            if key in conns:
                conns[key].app_view_hex = bytes(appview_buf)
                conns[key].app_view_declared_len = int(m["len"])
            appview_key = None
            appview_buf = bytearray()
            continue

        if appview_key is not None:
            m = RE_HEXDUMP_LINE.match(line)
            if m:
                hex_part = m.group(2).strip()
                for byte_s in hex_part.split():
                    appview_buf.append(int(byte_s, 16))

    return conns


# === Correlation + verdict ===

@dataclass
class Verdict:
    uid: str
    orig: str
    zeek_c2s_bytes: int
    backend_bytes: Optional[int]
    rexmit_count: int
    weird_count: int
    desync_reason: list[str] = field(default_factory=list)
    zeek_sample: Optional[bytes] = None
    backend_sample: Optional[bytes] = None
    diff_offset: Optional[int] = None

    @property
    def desync(self) -> bool:
        return bool(self.desync_reason)


def correlate(
    zeek_conns: dict[str, ZeekConn],
    backend_conns: dict[tuple[str, int], BackendConn],
) -> list[Verdict]:
    verdicts: list[Verdict] = []

    for uid, zc in zeek_conns.items():
        key = (zc.orig_ip, zc.orig_port)
        bc = backend_conns.get(key)
        v = Verdict(
            uid=uid,
            orig=f"{zc.orig_ip}:{zc.orig_port}",
            zeek_c2s_bytes=zc.c2s_total_len,
            backend_bytes=bc.total_bytes if bc else None,
            rexmit_count=len(zc.rexmits),
            weird_count=len(zc.weirds),
        )

        if bc is None:
            v.desync_reason.append("no matching backend connection")
        else:
            if bc.total_bytes is not None and zc.c2s_total_len != bc.total_bytes:
                v.desync_reason.append(
                    f"byte-count mismatch: zeek_c2s={zc.c2s_total_len} backend={bc.total_bytes}"
                )
            # Content check for Phase 2 overlap/partial: compare Zeek delivered bytes vs backend
            # (preview concat from tcp_contents gives the reassembled C->S bytes Zeek delivered
            # to scriptland / upper layers; for lab payloads <256B this is the full stream)
            # Use unescaper so binary bytes (\xff in partial evil, etc.) round-trip correctly from Zeek's print fmt
            preview = _unescape_zeek_preview(zc.c2s_preview_concat)
            backend_head = bc.app_view_hex[: max(len(preview), 64)]
            v.zeek_sample = preview
            v.backend_sample = bc.app_view_hex[: max(len(preview), 64)]
            # Direct prefix compare (after loose for Zeek escapes) + best-effort for safety
            if preview and backend_head:
                stripped = _loose_strip(preview)
                if not bc.app_view_hex.startswith(stripped) and not _bytes_compatible(preview, backend_head):
                    off = _first_diff_offset(preview, bc.app_view_hex)
                    v.diff_offset = off
                    v.desync_reason.append(
                        f"content diverges at offset {off}: Zeek reassembled != backend received"
                    )

        if zc.weirds:
            names = ",".join(sorted({w[0] for w in zc.weirds}))
            v.desync_reason.append(f"reassembly weirds: {names}")

        verdicts.append(v)

    # Surface backend connections Zeek never saw (would indicate inspector blindness)
    seen = {(z.orig_ip, z.orig_port) for z in zeek_conns.values()}
    for (ip, port), bc in backend_conns.items():
        if (ip, port) not in seen:
            verdicts.append(Verdict(
                uid="<none>",
                orig=f"{ip}:{port}",
                zeek_c2s_bytes=0,
                backend_bytes=bc.total_bytes,
                rexmit_count=0,
                weird_count=0,
                desync_reason=["no matching Zeek connection (inspector missed it)"],
            ))

    return verdicts


def _loose_strip(s: bytes) -> bytes:
    # Zeek's print escapes some bytes; lossy comparison helper.
    return s.replace(b"\\x", b"").replace(b"\\n", b"").replace(b"\\r", b"")


def _bytes_compatible(zeek_preview: bytes, backend_head: bytes) -> bool:
    """Best-effort: do the printable runs of zeek_preview appear in backend_head in order?"""
    import re as _re
    runs = _re.findall(rb"[ -~]{4,}", zeek_preview)
    cursor = 0
    for run in runs:
        idx = backend_head.find(run, cursor)
        if idx < 0:
            return False
        cursor = idx + len(run)
    return True


def _first_diff_offset(a: bytes, b: bytes) -> int:
    """Return byte offset of first difference, or -1 if identical up to min len."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else -1


def _short_hex(b: bytes, max_len: int = 32) -> str:
    """Compact hexdump prefix for evidence in reports."""
    if not b:
        return "(empty)"
    h = " ".join(f"{x:02x}" for x in b[:max_len])
    if len(b) > max_len:
        h += " ..."
    return h


def _unescape_zeek_preview(s: str) -> bytes:
    """Recover actual bytes from Zeek print fmt output (handles \\xHH escapes for binary/partial cases)."""
    if not s:
        return b""
    # Replace \xHH with the byte; handle common escapes first
    def hex_repl(m):
        return chr(int(m.group(1), 16))
    s = re.sub(r'\\x([0-9a-fA-F]{2})', hex_repl, s)
    s = s.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\\\', '\\').replace('\\0', '\0')
    return s.encode('latin-1', errors='replace')


# === Reporting ===

def render(verdicts: list[Verdict]) -> tuple[str, int]:
    lines = []
    lines.append("=" * 78)
    lines.append("TRS Desync Analysis")
    lines.append("=" * 78)

    desync_count = 0
    for v in verdicts:
        marker = "DESYNC" if v.desync else "ok    "
        lines.append("")
        lines.append(f"[{marker}] {v.orig}   (zeek_uid={v.uid})")
        lines.append(f"    zeek C->S bytes:    {v.zeek_c2s_bytes}")
        lines.append(f"    backend bytes:      {v.backend_bytes if v.backend_bytes is not None else '<no log>'}")
        lines.append(f"    retransmits:        {v.rexmit_count}")
        lines.append(f"    reassembly weirds:  {v.weird_count}")
        if v.desync:
            desync_count += 1
            for reason in v.desync_reason:
                lines.append(f"    REASON: {reason}")
            # For Phase 2 overlap/partial: show concrete hex evidence of the desync
            if v.zeek_sample is not None and v.backend_sample is not None:
                lines.append(f"    Zeek reassembled (hex): {_short_hex(v.zeek_sample)}")
                lines.append(f"    Backend received  (hex): {_short_hex(v.backend_sample)}")
                if v.diff_offset is not None and v.diff_offset >= 0:
                    lines.append(f"    First diff byte offset: {v.diff_offset}")

    lines.append("")
    lines.append("-" * 78)
    lines.append(f"Total connections: {len(verdicts)}    desync: {desync_count}")
    lines.append("-" * 78)

    exit_code = 2 if desync_count else 0
    return "\n".join(lines), exit_code


def main() -> int:
    p = argparse.ArgumentParser(description="TRS desync analyzer")
    p.add_argument("--zeek", type=Path, required=True, help="Zeek stdout (from local.zeek)")
    p.add_argument("--backend", type=Path, required=True, help="Backend container log")
    args = p.parse_args()

    if not args.zeek.exists():
        print(f"ERROR: zeek file not found: {args.zeek}", file=sys.stderr)
        return 1
    if not args.backend.exists():
        print(f"ERROR: backend file not found: {args.backend}", file=sys.stderr)
        return 1

    zeek_conns = parse_zeek(args.zeek)
    backend_conns = parse_backend(args.backend)

    if not zeek_conns and not backend_conns:
        print("ERROR: no connections found in either input", file=sys.stderr)
        return 1

    verdicts = correlate(zeek_conns, backend_conns)
    report, code = render(verdicts)
    print(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
