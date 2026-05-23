# TCP Retransmission Smuggling (TRS) Lab

**White-hat, lab-only defensive research** into a novel L4 evasion class that exploits inconsistencies in how stateful inspectors (Zeek, Suricata, WAFs, etc.) handle TCP retransmissions compared with the real endpoint.

This repository contains a complete, reproducible Docker Compose lab that lets researchers:

- Generate controlled TCP retransmissions (natural loss via `tc netem` + future raw-socket overlapping/spurious retransmits)
- Capture every segment on the wire (middle L3 router + tcpdump)
- Compare what Zeek's reassembly engine saw vs. what the backend application actually received
- Iterate on detection and mitigation ideas

Everything runs in an isolated bridge topology (no host exposure, no external traffic).

---

## Quick Start

```powershell
# 1. Build & bring up
docker compose build
docker compose up -d

# 2. Send the actual TRS overlap primitive (raw-socket, two segments at same seq)
docker compose run --rm attacker python /app/generator.py --case overlap --count 1

# 3. Run Zeek on the right-leg pcap
$pcap = (Get-ChildItem pcaps\right-*.pcap | Sort LastWriteTime -Descending | Select -First 1).Name
docker compose --profile zeek run --rm zeek `
    zeek -C -r /pcaps/$pcap /zeek-config/local.zeek > zeek-run.txt 2>&1

# 4. Capture backend log and diff
docker compose logs --no-color backend > backend.log
python scripts\analyze.py --zeek zeek-run.txt --backend backend.log
```

Exit code from `analyze.py`: `0` no desync, `2` desync detected, `1` parse error.

Full instructions, architecture, and the exact commands for baseline vs. loss-induced retransmission are in:

- **[docs/runbook.md](docs/runbook.md)** — step-by-step reproduction guide

---

## Repository Layout

```
docker-compose.yml          # 4-service isolated L3 topology (attacker, middle, backend, zeek)
compose/
  attacker/
    generator.py            # Test-case runner (baseline, loss, overlap, spurious, partial)
    raw_tcp.py              # Stdlib userland TCP/IPv4 client over raw sockets
    Dockerfile
  backend/
    logger.py               # Pure-TCP server; hexdumps every byte the app receives
    Dockerfile
  middle/
    entrypoint.sh           # L3 router + per-leg rolling pcap + impair-{left,right} helpers
    Dockerfile
configs/
  zeek/local.zeek           # TCP reassembly + retransmit + weird event logging
pcaps/                      # left-*.pcap and right-*.pcap (rotating, bind-mounted)
docs/
  runbook.md                # Step-by-step lab manual
scripts/
  analyze.py                # Parses Zeek output + backend log; flags desync per connection
plan.txt                    # Original research brief (scope, phases, success criteria)
```

---

## Current Status

**Phase 1 (lab infrastructure)** — complete
- Isolated routed topology with deterministic subnets
- Backend logs exact application-layer bytes (hexdump per connection)
- Per-leg rotating pcap captures (Ethernet frames, replayable into other IDSes)
- Live impairment helpers on the middle: `impair-right loss|drop|delay|clear`
  (deterministic-drop mode for reproducibility, not just random `netem`)
- Zeek config that prints `TCP_REXMIT`, `TCP_CONTENTS`, `TCP_WEIRD`, conn lifecycle

**Phase 2 (TRS primitives)** — implemented, awaiting validation
- Stdlib userland TCP client (`raw_tcp.py`) with full handshake/data/FIN
- `--case overlap` — two segments at same seq with different content
- `--case spurious` — duplicate post-ACK retransmits
- `--case partial` — Ptacek/Newsham-style partial-overlap shape
- Automated `analyze.py` that diffs Zeek's reassembled view vs the backend's
  delivered bytes per connection and emits a desync verdict

**Phase 3 (extensions)** — pending
- Suricata + ModSecurity service variants
- Live Zeek (network-namespace sidecar on middle) instead of offline pcap
- Encoding-confusion overlap cases (UTF-8 vs Windows-1252 best-fit)
- Byte-exact reassembly diff using Python pcap parsing (currently we diff
  Zeek's text-event previews against backend hexdumps)

See `plan.txt` for the full research questions, threat model, and deliverable list.

---

## Ethical Notice

**This is 100% authorized defensive research only.**

- All activity stays inside the Docker lab network.
- No scanning, no external targets, no production use.
- Goal: improve detection of a previously under-studied evasion class and help vendors harden their stream reassemblers.

If you discover a genuine, previously unknown vulnerability in any open-source inspector while extending this work, follow responsible disclosure.

---

## Contributing / Extending

Pull requests that add:

- New test cases (charset, encoding, overlap with different content, etc.)
- Suricata / Snort / WAF containers + logging
- Automated analysis scripts that quantify desync
- Mitigation ideas or Zeek scripts that raise on retransmit anomalies

…are very welcome.

Start by reading `plan.txt` and `docs/runbook.md`, then open an issue or PR.

---

## References & Further Reading

- The original prompt in `plan.txt`
- Zeek TCP reassembly documentation and events (`tcp_rexmit`, `tcp_contents`, etc.)
- Classic papers on TCP reassembly evasion and "desync" attacks (1990s–2000s IDS literature)
- Modern work on HTTP/2, QUIC, and L4 smuggling analogs

---

**Status**: The lab now generates the actual TRS primitives (overlap, spurious,
partial) via a stdlib raw-socket TCP client and ships an automated desync
detector. The raw-socket path has been implemented but not yet end-to-end
validated in a fully bootstrapped container — first runs may surface kernel
quirks (TX checksum offload, bridge filter rules) that need iterating on.
See `docs/runbook.md` §11 for troubleshooting.

Happy researching!
