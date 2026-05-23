#!/usr/bin/env python3
"""
Minimal userland TCP/IPv4 client over raw sockets.

Purpose: emit TCP segments with precisely chosen seq numbers — including
overlapping retransmits with different content — to study how stateful
inspectors handle retransmit asymmetry vs the application endpoint.

NOT a general-purpose stack. Assumptions:
- IPv4 only
- One connection at a time per process
- No TCP options negotiation (peer falls back to defaults)
- No window scaling / SACK
- Small payloads (<= 1400 bytes per segment)
- Caller installs iptables RST suppression for our src_port BEFORE open()
- Lab use only

References:
    RFC 793 (classic) / RFC 9293 (TCP)
"""

from __future__ import annotations

import os
import random
import select
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


# === TCP flag bits ===
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


# === Checksum helpers ===

def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_segment),
    )
    return (~_ones_complement_sum(pseudo + tcp_segment)) & 0xFFFF


# === Segment dataclass + (de)serialization ===

@dataclass
class Segment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int = 65535
    payload: bytes = b""


def build_tcp(src_ip: str, dst_ip: str, seg: Segment) -> bytes:
    """Return wire-ready TCP header+payload (kernel adds IPv4 header on send)."""
    data_offset_words = 5  # no options
    offset_and_reserved = data_offset_words << 4

    header = struct.pack(
        "!HHIIBBHHH",
        seg.src_port,
        seg.dst_port,
        seg.seq & 0xFFFFFFFF,
        seg.ack & 0xFFFFFFFF,
        offset_and_reserved,
        seg.flags,
        seg.window,
        0,           # checksum placeholder
        0,           # urgent pointer
    )
    chksum = _tcp_checksum(src_ip, dst_ip, header + seg.payload)
    header = header[:16] + struct.pack("!H", chksum) + header[18:]
    return header + seg.payload


def parse_tcp(packet: bytes) -> Optional[Segment]:
    """Parse a raw IPv4+TCP packet. Returns None if it's not a valid TCP packet."""
    if len(packet) < 20:
        return None
    ip_ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ip_ihl + 20:
        return None
    tcp = packet[ip_ihl:]
    src_port, dst_port, seq, ack, off_and_res, flags, window, _chk, _urg = struct.unpack(
        "!HHIIBBHHH", tcp[:20]
    )
    data_offset = (off_and_res >> 4) * 4
    if len(tcp) < data_offset:
        return None
    return Segment(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        payload=tcp[data_offset:],
    )


def get_outbound_ip_for(dst_ip: str) -> str:
    """Which local IP would the kernel use to reach dst_ip? No packets sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


# === Kernel RST suppression ===
# The local kernel has no socket for our raw-driven src_port. When it sees
# incoming SYN-ACK / data on that port, it will helpfully RST the peer.
# We must drop outbound RSTs for our src_port for the duration of the session.

def suppress_kernel_rst(src_port: int) -> None:
    subprocess.run(
        ["iptables", "-A", "OUTPUT",
         "-p", "tcp", "--tcp-flags", "RST", "RST",
         "--sport", str(src_port), "-j", "DROP"],
        check=True,
    )


def restore_kernel_rst(src_port: int) -> None:
    subprocess.run(
        ["iptables", "-D", "OUTPUT",
         "-p", "tcp", "--tcp-flags", "RST", "RST",
         "--sport", str(src_port), "-j", "DROP"],
        check=False,
    )


# === Session ===

class RawTcpSession:
    """
    Userland TCP/IPv4 client. Send/receive via SOCK_RAW + IPPROTO_TCP.

    Typical flow:
        with RawTcpSession("10.20.0.2", 8080) as s:
            s.open()
            s.send_data(b"GET /\\r\\n")          # advances snd_seq
            s.inject_at(s.last_data_seq, b"EVL") # overlap at same seq
            s.close()
    """

    def __init__(
        self,
        dst_ip: str,
        dst_port: int,
        src_port: Optional[int] = None,
        initial_seq: Optional[int] = None,
    ):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = get_outbound_ip_for(dst_ip)
        self.src_port = src_port if src_port is not None else random.randint(40000, 60000)

        self.iss = initial_seq if initial_seq is not None else random.randint(0x10000000, 0x70000000)
        self.snd_seq = self.iss          # next byte we'll send
        self.last_data_seq = self.iss    # seq of the most recent data segment (set after send_data)
        self.last_data_len = 0
        self.rcv_next = 0                # next byte we expect from peer

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Default IP_HDRINCL=0 -> kernel builds IPv4 header for us

        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.recv_sock.bind((self.src_ip, 0))
        self.recv_sock.setblocking(False)

        self._opened = False
        self._rst_installed = False

    # ---- low-level send ----

    def _send(
        self,
        flags: int,
        payload: bytes = b"",
        seq: Optional[int] = None,
        ack: Optional[int] = None,
    ) -> None:
        seg = Segment(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq=self.snd_seq if seq is None else seq,
            ack=self.rcv_next if ack is None else ack,
            flags=flags,
            payload=payload,
        )
        wire = build_tcp(self.src_ip, self.dst_ip, seg)
        self.send_sock.sendto(wire, (self.dst_ip, self.dst_port))

    # ---- low-level receive ----

    def _recv_match(
        self,
        flags_mask: int,
        flags_want: int,
        timeout: float = 5.0,
    ) -> Optional[Segment]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            r, _, _ = select.select([self.recv_sock], [], [], remaining)
            if not r:
                return None
            try:
                data, _ = self.recv_sock.recvfrom(65535)
            except BlockingIOError:
                continue
            seg = parse_tcp(data)
            if seg is None:
                continue
            if seg.src_port != self.dst_port or seg.dst_port != self.src_port:
                continue
            if (seg.flags & flags_mask) == flags_want:
                return seg

    # ---- public API ----

    def install_rst_suppression(self) -> None:
        if not self._rst_installed:
            suppress_kernel_rst(self.src_port)
            self._rst_installed = True

    def open(self, timeout: float = 5.0) -> None:
        if not self._rst_installed:
            self.install_rst_suppression()

        # SYN
        self._send(flags=SYN, ack=0)
        synack = self._recv_match(SYN | ACK | RST, SYN | ACK, timeout=timeout)
        if synack is None:
            raise TimeoutError(f"no SYN-ACK from {self.dst_ip}:{self.dst_port}")

        self.rcv_next = (synack.seq + 1) & 0xFFFFFFFF
        self.snd_seq = (self.snd_seq + 1) & 0xFFFFFFFF   # SYN consumes 1
        self._send(flags=ACK)
        self._opened = True

    def send_data(self, payload: bytes, push: bool = True) -> int:
        """Normal data segment; advances snd_seq. Returns seq used."""
        if not self._opened:
            raise RuntimeError("session not opened")
        used_seq = self.snd_seq
        flags = ACK | (PSH if push else 0)
        self._send(flags=flags, payload=payload)
        self.snd_seq = (self.snd_seq + len(payload)) & 0xFFFFFFFF
        self.last_data_seq = used_seq
        self.last_data_len = len(payload)
        return used_seq

    def inject_at(
        self,
        seq: int,
        payload: bytes,
        flags: int = PSH | ACK,
    ) -> None:
        """
        Emit an extra segment with chosen seq + content; does NOT advance snd_seq.

        This is the TRS primitive. The most useful patterns:
          * Spurious retransmit: seq == last_data_seq, payload == previous content
          * Overlap, different content: seq == last_data_seq, payload != previous
          * Partial overlap: seq in (last_data_seq, last_data_seq + last_data_len)
        """
        if not self._opened:
            raise RuntimeError("session not opened")
        self._send(flags=flags, payload=payload, seq=seq)

    def drain(self, duration: float = 0.5) -> None:
        """Read and discard any pending peer data for `duration` seconds."""
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.recv_sock], [], [], deadline - time.monotonic())
            if not r:
                return
            try:
                data, _ = self.recv_sock.recvfrom(65535)
            except BlockingIOError:
                continue
            seg = parse_tcp(data)
            if seg and seg.src_port == self.dst_port and seg.dst_port == self.src_port:
                if seg.payload:
                    self.rcv_next = (seg.seq + len(seg.payload)) & 0xFFFFFFFF
                    self._send(flags=ACK)
                if seg.flags & FIN:
                    self.rcv_next = (self.rcv_next + 1) & 0xFFFFFFFF
                    self._send(flags=ACK)

    def close(self, timeout: float = 3.0) -> None:
        if not self._opened:
            return
        self._send(flags=FIN | ACK)
        self.snd_seq = (self.snd_seq + 1) & 0xFFFFFFFF
        fin = self._recv_match(FIN, FIN, timeout=timeout)
        if fin is not None:
            self.rcv_next = (fin.seq + 1) & 0xFFFFFFFF
            self._send(flags=ACK)
        self._opened = False

    # ---- cleanup ----

    def cleanup(self) -> None:
        try:
            self.send_sock.close()
        except OSError:
            pass
        try:
            self.recv_sock.close()
        except OSError:
            pass
        if self._rst_installed:
            restore_kernel_rst(self.src_port)
            self._rst_installed = False

    def __enter__(self) -> "RawTcpSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.close()
        except Exception:
            pass
        self.cleanup()
