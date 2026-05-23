# TRS Lab Runbook — TCP Retransmission Smuggling (L4 Echo Desync)

This runbook walks through reproducing each test case from scratch on a
Docker Desktop (Windows) host. All commands assume the repo root is the
current directory.

---

## Topology

```
 attacker (10.10.0.2)  --left-->  middle  --right-->  backend (10.20.0.2)
                                  (router + tcpdump + tc/iptables)
```

- All impairments (`netem loss`, `iptables drop`, `netem delay`) live on the
  **middle** container's `right` interface — that is the leg between the
  inspector vantage point and the backend, which is what creates the
  inspector-vs-application asymmetry we are studying.
- `tcpdump` runs on **both** legs separately and writes rotating per-leg
  pcaps into `./pcaps/`.

---

## 0. Prerequisites

- Docker Desktop with WSL2 backend.
- Linux containers (default on Windows DD).
- Repo root = directory with `docker-compose.yml`.

---

## 1. Build & bring up

```powershell
docker compose build
New-Item -ItemType Directory -Path pcaps -Force | Out-Null
docker compose up -d
docker compose ps
```

You should see `trs-backend`, `trs-attacker`, `trs-middle` running. The
Zeek image is pulled on first use via the `zeek` profile.

Confirm the middle started its captures and impair helpers:

```powershell
docker compose logs middle | Select-String "Left leg|Right leg|tcpdump PIDs"
docker compose exec middle ls /usr/local/bin/impair-right
```

---

## 2. Case: baseline (kernel TCP, clean)

```powershell
docker compose run --rm attacker python /app/generator.py --case baseline --count 3
```

Expected:
- Backend logs three full HTTP requests delivered.
- `pcaps/right-*.pcap` shows three TCP flows with no retransmissions.
- Zeek run yields no `TCP_REXMIT`, three `CONN_EST` / `CONN_END` pairs.

---

## 3. Case: kernel-driven retransmits (loss on the right leg)

```powershell
# Apply 8% loss + 10ms delay on the middle->backend leg
docker compose exec middle impair-right loss 8 10

# Run a few iterations
docker compose run --rm attacker python /app/generator.py --case loss --count 5

# Clear impairment
docker compose exec middle impair-right clear
```

Expected:
- Backend still receives the full payload (kernel retransmits cover the loss).
- `pcaps/right-*.pcap` shows duplicate seq numbers (`tcp.analysis.retransmission`).
- Zeek prints one or more `TCP_REXMIT` lines per affected connection.
- analyze.py reports `ok` (no desync; this case has identical payload on
  every retransmit — the lab works but no asymmetry is induced).

For **deterministic** loss (better for repeatability than random `netem`):

```powershell
docker compose exec middle impair-right drop every 5
docker compose run --rm attacker python /app/generator.py --case loss --count 3
docker compose exec middle impair-right clear
```

---

## 4. Case: overlap (the actual TRS primitive)

Two segments are sent at the SAME seq with DIFFERENT content. The backend
will accept the first; the inspector's reassembly engine may pick either.

```powershell
docker compose run --rm attacker python /app/generator.py --case overlap --count 1
```

In the attacker output you should see:

```
[generator] overlap: raw-socket — benign then overlapping evil at same seq
[generator]   src_port=NNNNN iss=0x...
[generator]   handshake OK
[generator]   sent BENIGN (NNN bytes) at seq=...
[generator]   injected OVERLAP (NNN bytes) at same seq=...
```

Backend will log the bytes it *actually* delivered to the application.
Zeek's `TCP_CONTENTS` lines will show what the inspector reassembled.

To space the two segments out (giving the inspector more chance to
finalize the first one before the overlap arrives):

```powershell
docker compose run --rm attacker python /app/generator.py --case overlap --overlap-delay 0.05
```

---

## 5. Case: spurious retransmit

```powershell
docker compose run --rm attacker python /app/generator.py --case spurious --spurious-count 3
```

Sends the payload, lets the backend ACK it, then re-sends the same segment
3 extra times. Some inspectors re-inspect, some don't — that's the test.

---

## 6. Case: partial overlap

```powershell
docker compose run --rm attacker python /app/generator.py --case partial --partial-offset 8
```

Sends BENIGN at seq=X, then a different payload at seq=X+8 that overwrites
the tail of BENIGN AND extends past it. This is the classic Ptacek/Newsham
shape adapted for the retransmit class.

---

## 7. Analysis

After each run:

```powershell
# Latest right-leg pcap
$pcap = (Get-ChildItem pcaps\right-*.pcap | Sort LastWriteTime -Descending | Select -First 1).Name

# Run Zeek on it with our local.zeek; capture stdout
docker compose --profile zeek run --rm zeek `
    zeek -C -r /pcaps/$pcap /zeek-config/local.zeek > zeek-run.txt 2>&1

# Capture the backend log for this run
docker compose logs --no-color backend > backend.log

# Diff
python scripts\analyze.py --zeek zeek-run.txt --backend backend.log
```

Exit code:
- `0` — no desync detected
- `2` — at least one connection shows divergence between Zeek's reassembled
        view and the backend's delivered bytes
- `1` — parse error / missing input

Sample desync output:

```
[DESYNC] 10.10.0.2:54123   (zeek_uid=CXXXXX)
    zeek C->S bytes:    421
    backend bytes:      189
    retransmits:        2
    reassembly weirds:  1
    REASON: byte-count mismatch: zeek_c2s=421 backend=189
    REASON: reassembly weirds: rexmit_inconsistency
```

---

## 8. Inspecting captures manually

```powershell
$pcap = (Get-ChildItem pcaps\right-*.pcap | Sort LastWriteTime -Descending | Select -First 1).FullName

# Quick io stats
docker compose --profile zeek run --rm zeek tshark -r /pcaps/$(Split-Path $pcap -Leaf) -q -z io,stat,1

# Only retransmissions
docker compose --profile zeek run --rm zeek `
    tshark -r /pcaps/$(Split-Path $pcap -Leaf) -Y "tcp.analysis.retransmission"
```

In Wireshark on the Windows host, open `pcaps\right-*.pcap` directly.

---

## 9. Live impairment control on the middle

```powershell
# Show current state on the right leg
docker compose exec middle impair-right show

# Random loss
docker compose exec middle impair-right loss 5

# Random loss + delay
docker compose exec middle impair-right loss 5 20

# Deterministic drop every Nth TCP packet
docker compose exec middle impair-right drop every 7

# Pure latency
docker compose exec middle impair-right delay 50 10

# Clear everything on this leg
docker compose exec middle impair-right clear
```

Same commands exist as `impair-left` for the attacker→middle leg.

---

## 10. Cleanup

```powershell
docker compose down
Remove-Item pcaps\* -Force      # optional
```

---

## 11. Troubleshooting

- **`overlap`/`spurious`/`partial` errors with `EPERM` or `[Errno 1]`** —
  the attacker container must have `NET_RAW` + `NET_ADMIN` (already set in
  `docker-compose.yml`). Verify with:
  ```powershell
  docker compose exec attacker capsh --print
  ```

- **No SYN-ACK in raw-socket cases** — the kernel RST suppression rule may
  not have installed. Inspect:
  ```powershell
  docker compose exec attacker iptables -L OUTPUT -n -v
  ```
  You should see a `DROP tcp ... flags:0x04/0x04 spt:<src_port>` rule while
  a session is open. If you killed the generator mid-run, the rule may be
  stuck; clear it manually:
  ```powershell
  docker compose exec attacker iptables -F OUTPUT
  ```

- **Empty Zeek `TCP_CONTENTS`** — Zeek may have ignored a flow due to bad
  checksum. We send via raw sockets and compute checksums in Python; if
  you see `bad_TCP_checksum` weirds, the path between attacker→middle is
  mangling something (rare in pure Linux bridge networks).

- **`impair-right` says "Cannot find device"** — interface autodetection
  fell back to the wrong name. Inspect:
  ```powershell
  docker compose exec middle ip -br addr
  ```
  And edit `compose/middle/entrypoint.sh` to set `LEFT_IF` / `RIGHT_IF`
  explicitly.

---

## 12. Extending

- **Add Suricata**: drop a `suricata` service with the same `pcaps/`
  bind-mount; run offline `suricata -r /pcaps/right-*.pcap` and add a
  Suricata-output parser to `analyze.py`.
- **Add Snort** likewise.
- **More overlap shapes** in `generator.py` (see `case_partial` for a
  template).
- **Encoding-confusion overlap**: same-length overlap where the two payloads
  decode differently under different charset assumptions (UTF-8 vs
  Windows-1252 best-fit). Add as a new case alongside `overlap`.
- **Live Zeek**: run Zeek as a sidecar on the middle's interface instead of
  offline pcap analysis (requires `network_mode: container:trs-middle` or
  `cap_add: NET_ADMIN` on a Zeek container sharing the middle's net ns).
