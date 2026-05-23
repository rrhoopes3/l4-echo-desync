#!/usr/bin/env python3
"""
TRS Desync Analyzer (stub / Phase 1)

Goal (see plan.txt Phase 3 & 8):
    Given a pcap + Zeek logs (or zeek conn.log/weird.log) + the backend application log,
    automatically flag any case where the stream that Zeek reassembled and delivered
    to its scriptland differs from the exact bytes the backend application received.

For v1 this is a manual process (see docs/runbook.md):
    1. Run a test case (baseline or loss)
    2. Capture the pcap from pcaps/
    3. Run Zeek on it with local.zeek → look for TCP_REXMIT / TCP_CONTENTS
    4. Compare the last "APPLICATION VIEW" block from the backend container logs
       with what Zeek printed for TCP_CONTENTS for the same connection UID.

Future improvements (high value):
    - Parse Zeek's ascii logs (conn.log, weird.log, or the custom print statements)
    - Correlate by 4-tuple + approximate time or by the UID that Zeek assigns
    - Extract the exact reassembled payload Zeek gave to the app layer
    - Diff against the backend's "exact bytes delivered"
    - Emit a structured report: "desync detected", "retransmit count", "bytes lost/gained", severity

Usage (once implemented):
    python scripts/analyze.py --zeek-log zeek-output.txt --backend-log backend.log --pcap pcaps/xxx.pcap

This file is intentionally small today so the lab can be used immediately.
The runbook already gives you everything you need to answer the first research questions.
"""

import argparse
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description="TRS desync detector (stub)")
    p.add_argument("--zeek-output", type=Path, help="Output of 'zeek ... local.zeek'")
    p.add_argument("--backend-log", type=Path, help="Captured backend stdout/stderr")
    p.add_argument("--pcap", type=Path, help="The pcap that was fed to Zeek")
    args = p.parse_args()

    print("TRS Analyze — Phase 1 stub")
    print("For now please follow docs/runbook.md for manual comparison.")
    print("When you have real logs, implement the correlation logic here.")
    print("Example files you would feed:")
    if args.zeek_output:
        print(f"  Zeek:   {args.zeek_output}")
    if args.backend_log:
        print(f"  Backend:{args.backend_log}")
    if args.pcap:
        print(f"  Pcap:   {args.pcap}")
    print("\nSee plan.txt 'Phase 3: Observation & Measurement' and 'Phase 8' for the spec.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
