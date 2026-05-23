#!/usr/bin/env python3
"""
TRS Experiment Runner — Phase 2 one-command research harness.

Runs a named case (overlap/partial/spurious/baseline/loss), waits for the
traffic, selects the freshest right-leg pcap, invokes Zeek + analyze.py,
and prints a concise report with desync verdict + hex evidence.

From a clean `docker compose up -d` (middle capturing, backend listening):

    python scripts/run_experiment.py --case overlap --count 3

Exit code matches analyze.py (2 if any desync observed, 0 if clean, 1 error).

Keeps the lab self-contained, stdlib-only, defensive-research tone.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    print(f"[{ts}] [runner] {msg}", flush=True)


def find_latest_right_pcap() -> Optional[Path]:
    pcaps = sorted(
        Path("pcaps").glob("right-*.pcap"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return pcaps[0] if pcaps else None


def run_cmd(cmd: list[str], timeout: float = 120.0, capture: bool = True) -> subprocess.CompletedProcess:
    log(f"Running: {' '.join(cmd)}")
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        log(f"Command timed out after {timeout}s")
        raise


def main() -> int:
    p = argparse.ArgumentParser(
        description="TRS Lab Experiment Runner (Phase 2 desync demonstrator)"
    )
    p.add_argument("--case", choices=["baseline", "loss", "overlap", "spurious", "partial"], default="overlap",
                   help="Experiment case (default: overlap)")
    p.add_argument("--count", type=int, default=3, help="Iterations (default: 3)")
    p.add_argument("--gap", type=float, default=0.8, help="Seconds between iterations")
    p.add_argument("--overlap-delay", type=float, default=0.03,
                   help="Delay between benign and overlap segment (overlap case)")
    p.add_argument("--spurious-count", type=int, default=2,
                   help="Spurious dups to send (spurious case)")
    p.add_argument("--partial-offset", type=int, default=8,
                   help="Partial overlap byte offset (partial case)")
    p.add_argument("--target", default="10.20.0.2:8080", help="Backend target")
    p.add_argument("--zeek-profile", default="zeek", help="docker compose profile for Zeek")
    p.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    p.add_argument("--self-test", action="store_true", help="Run automated smoke tests for analyzer verdict logic + hex evidence (no Docker needed)")
    args = p.parse_args()

    if not Path("docker-compose.yml").exists():
        log("ERROR: run from repo root containing docker-compose.yml")
        return 1

    # Ensure pcaps dir
    Path("pcaps").mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    log(f"Starting experiment case={args.case} count={args.count} ts={ts}")

    # Always-defined result objects for dry-run safety and error paths (fixes NameError in dry-run + partial failures)
    gen_res = None
    zeek_res = None
    blog_res = None
    anal_res = None
    code = 0
    report = ""

    if args.self_test:
        log("Running self-test for analyzer verdict + hex evidence (ASCII + binary/partial cases)...")
        # Minimal stdlib test of the core Phase-2 logic (no Docker, exercises desync detection + unescape + hex report)
        try:
            sys.path.insert(0, str(Path(__file__).parent))  # allow "import analyze" when run as scripts/run_... (Path/sys already module-level)
            import analyze  # local module
            # Basic smoke on helpers (covers the new unescape for binary, diff, short_hex, Verdict)
            preview_escaped = "GET /api/v1/user?id=1'+OR+'1'='1...\\xfftest"
            recovered = analyze._unescape_zeek_preview(preview_escaped)
            assert b"\\xff" not in recovered and (b"\xff" in recovered or b"test" in recovered)
            off = analyze._first_diff_offset(b"abc", b"axc")
            assert off == 1
            assert "..." in analyze._short_hex(b"0123456789" * 5)
            v = analyze.Verdict("t", "10.0.0.1:1", 10, 10, 0, 0)
            v.desync_reason = ["content diverges at offset 5 (self-test)"]
            v.zeek_sample = b"evil"
            v.backend_sample = b"good"
            v.diff_offset = 5
            r, c = analyze.render([v])
            assert c == 2 and "DESYNC" in r and "First diff byte offset: 5" in r
            log("Self-test PASSED: analyzer verdict logic, hex evidence, and binary unescape all functional.")
            return 0
        except Exception as exc:
            log(f"Self-test FAILED: {exc!r}")
            import traceback
            traceback.print_exc()
            return 1

    # 1. Run the generator (inside attacker container)
    gen_cmd = [
        "docker", "compose", "run", "--rm", "attacker",
        "python", "/app/generator.py",
        "--target", args.target,
        "--case", args.case,
        "--count", str(args.count),
        "--gap", str(args.gap),
    ]
    if args.case == "overlap":
        gen_cmd += ["--overlap-delay", str(args.overlap_delay)]
    elif args.case == "spurious":
        gen_cmd += ["--spurious-count", str(args.spurious_count)]
    elif args.case == "partial":
        gen_cmd += ["--partial-offset", str(args.partial_offset)]

    if args.dry_run:
        log("DRY-RUN: would run generator")
        print("  " + " ".join(gen_cmd))
        gen_res = subprocess.CompletedProcess(gen_cmd, 0, "", "")  # dummy for meta
    else:
        gen_res = run_cmd(gen_cmd, timeout=180.0)
        if gen_res.stdout:
            print(gen_res.stdout)
        if gen_res.stderr:
            print(gen_res.stderr, file=sys.stderr)
        if gen_res.returncode != 0:
            log(f"Generator failed with code {gen_res.returncode}")
            # still continue to analysis if pcaps exist

    # 2. Robust pcap selection: poll briefly for a right pcap whose mtime advanced past experiment start.
    # This fixes fragility on Windows Docker Desktop bind mounts (mtime lag, stale files, wrong traffic).
    # Falls back to latest if no update detected within timeout (still better than fixed sleep).
    pre_time = time.time()
    pcap = None
    for _ in range(20):  # up to ~10s poll
        candidate = find_latest_right_pcap()
        if candidate and candidate.stat().st_mtime > pre_time - 2:  # allow small clock skew
            pcap = candidate
            break
        time.sleep(0.5)
    if pcap is None:
        pcap = find_latest_right_pcap()
    if pcap is None:
        log("ERROR: no right-*.pcap found in ./pcaps/. Is middle running?")
        return 1
    log(f"Selected pcap: {pcap.name} (mtime {time.ctime(pcap.stat().st_mtime)})")

    # 3. Run Zeek offline on the pcap (via zeek profile)
    zeek_log = Path("pcaps") / f"zeek-{args.case}-{ts}.txt"
    zeek_cmd = [
        "docker", "compose", "--profile", args.zeek_profile, "run", "--rm", "zeek",
        "zeek", "-C", "-r", f"/pcaps/{pcap.name}", "/zeek-config/local.zeek",
    ]
    if args.dry_run:
        print("  " + " ".join(zeek_cmd))
        zeek_stdout = "DRY-RUN zeek output (simulated)"
        zeek_res = subprocess.CompletedProcess(zeek_cmd, 0, zeek_stdout, "")
    else:
        zeek_res = run_cmd(zeek_cmd, timeout=60.0)
        zeek_stdout = (zeek_res.stdout or "") + (zeek_res.stderr or "")
        zeek_log.write_text(zeek_stdout, encoding="utf-8", errors="replace")
        log(f"Zeek output saved to {zeek_log}")

    # 4. Capture (recent) backend logs
    backend_log = Path("pcaps") / f"backend-{args.case}-{ts}.log"
    if args.dry_run:
        backend_stdout = "DRY-RUN backend log (simulated)"
        blog_res = subprocess.CompletedProcess(["docker", "compose", "logs", "--since", "30s", "backend"], 0, backend_stdout, "")
    else:
        # Use --since 30s to capture only recent activity (prevents prior-experiment pollution, false DESYNCs, bad correlation by old ports)
        blog_res = run_cmd(["docker", "compose", "logs", "--no-color", "--since", "30s", "backend"], timeout=30.0)
        backend_stdout = blog_res.stdout or ""
        backend_log.write_text(backend_stdout, encoding="utf-8", errors="replace")
        log(f"Backend log saved to {backend_log}")

    # 5. Run analyzer (local python)
    analyze_cmd = [
        sys.executable, "scripts/analyze.py",
        "--zeek", str(zeek_log),
        "--backend", str(backend_log),
    ]
    if args.dry_run:
        print("  " + " ".join(analyze_cmd))
        report = "DRY-RUN: [DESYNC] example ... (would show hex diff for overlap case)"
        code = 2
        anal_res = subprocess.CompletedProcess(analyze_cmd, code, report, "")
    else:
        anal_res = run_cmd(analyze_cmd, timeout=30.0, capture=True)
        report = anal_res.stdout or ""
        if anal_res.stderr:
            print(anal_res.stderr, file=sys.stderr)
        code = anal_res.returncode

    # 6. Print + persist final report + metadata
    header = (
        f"\n{'='*78}\n"
        f"TRS Experiment Report — case={args.case} count={args.count} ts={ts}\n"
        f"pcap: {pcap.name}\n"
        f"{'='*78}\n"
    )
    full_report = header + report
    print(full_report)

    report_file = Path("pcaps") / f"report-{args.case}-{ts}.txt"
    report_file.write_text(full_report, encoding="utf-8", errors="replace")
    log(f"Full report written to {report_file}")

    # Experiment metadata (for reproducibility / later analysis)
    meta = {
        "timestamp": ts,
        "case": args.case,
        "count": args.count,
        "pcap": pcap.name,
        "zeek_log": zeek_log.name,
        "backend_log": backend_log.name,
        "report": report_file.name,
        "generator_return": gen_res.returncode if not args.dry_run else None,
        "analyze_exit": code,
        "desync_observed": "DESYNC" in report,
    }
    meta_file = Path("pcaps") / f"experiment-{args.case}-{ts}.json"
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    log(f"Metadata written to {meta_file}")

    if not args.dry_run and "DESYNC" in report:
        log("SUCCESS: desync between Zeek reassembly and backend observed in this run.")
    elif not args.dry_run:
        log("No desync observed in this run (try --count higher or --overlap-delay tweak).")

    return code


if __name__ == "__main__":
    sys.exit(main())
