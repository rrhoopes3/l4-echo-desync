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
# 1. Build the images
docker compose build

# 2. Bring the lab up
docker compose up -d

# 3. Run the first interesting experiment (loss → real retransmits)
docker compose run --rm attacker `
    python /app/generator.py --case loss --loss 8 --count 3

# 4. Watch what the backend actually got
docker compose logs -f backend

# 5. Analyze the latest pcap with Zeek (retransmit + reassembly events)
$pcap = (Get-ChildItem pcaps\*.pcap | Sort LastWriteTime -Descending | Select -First 1).Name
docker compose --profile zeek run --rm zeek `
    zeek -C -r /pcaps/$pcap /zeek-config/local.zeek
```

Full instructions, architecture, and the exact commands for baseline vs. loss-induced retransmission are in:

- **[docs/runbook.md](docs/runbook.md)** — step-by-step reproduction guide

---

## Repository Layout

```
docker-compose.yml          # 4-service isolated L3 topology (attacker, middle, backend, zeek)
compose/
  attacker/                 # generator.py + Dockerfile (raw + tc + iptables ready)
  backend/                  # pure-TCP logger that prints every byte the app receives
  middle/                   # Alpine L3 router + always-on tcpdump capture
  zeek/                     # (future) custom Zeek build if needed
configs/
  zeek/local.zeek           # Maximum-verbosity TCP reassembly + retransmit logging
pcaps/                      # Live capture files written by the middle (bind-mounted)
docs/
  runbook.md                # The lab manual
plan.txt                    # Original detailed research prompt (scope, phases, success criteria)
scripts/                    # (future) analysis helpers, result parsers
```

---

## Current Status (Phase 1 — MVP)

- ✅ Isolated routed topology with deterministic subnets
- ✅ Backend that logs the exact application-layer bytes
- ✅ Generator supporting baseline + loss-induced real retransmissions (kernel TCP)
- ✅ Always-on full-packet capture at the "inspection point"
- ✅ Zeek config that prints `TCP_REXMIT`, `TCP_CONTENTS`, conn lifecycle
- ✅ Runbook with reproducible commands for the first two test cases
- ⏳ Raw-socket hijack mode for *different-payload* overlapping retransmits (next)
- ⏳ Automated desync detector (Zeek logs vs. backend logs)
- ⏳ Suricata + ModSecurity variants

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

**Status**: Early but functional. The lab can already demonstrate real retransmitted TCP segments and log them differently from the application view.

Happy researching!
