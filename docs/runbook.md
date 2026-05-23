# TRS Lab Runbook — TCP Retransmission Smuggling (L4 Echo Desync)

This runbook shows how to bring up the isolated lab and execute the first two test cases:
1. **Baseline** — normal delivery, everything should be identical on wire / Zeek / backend.
2. **Loss-induced retransmission** — 5-10% random loss via `tc netem` causes the Linux TCP stack in the attacker to retransmit identical segments. We observe them in the pcap and Zeek logs, and confirm the backend still receives the correct data.

Later phases will add raw-socket crafted overlapping/spurious retransmissions with different payloads.

---

## 0. Prerequisites (Windows host with Docker Desktop)

- Docker Desktop (or Docker Engine + Compose v2) running and able to build Linux images.
- The current directory is the repo root (where `docker-compose.yml` lives).
- (Recommended) WSL2 backend enabled in Docker Desktop for best networking fidelity.
- You have `git` / editor if you want to tweak scripts.

No other dependencies on the Windows side.

---

## 1. One-time Setup

```powershell
# From B:\Grok\WH-tst003 (or your equivalent)
docker compose build
```

This builds:
- `trs-backend`
- `trs-attacker`
- `trs-middle` (router + live tcpdump capture)

The Zeek image (`zeek/zeek:6.0`) is pulled on first use via profile.

Create the capture directory (already bind-mounted):

```powershell
New-Item -ItemType Directory -Path pcaps -Force | Out-Null
```

---

## 2. Start the Lab (detached)

```powershell
docker compose up -d
```

Watch the services:

```powershell
docker compose ps
docker compose logs -f middle backend
```

You should see the backend announce it is listening on 0.0.0.0:8080.

The middle container is already running `tcpdump -i any ...` and writing timestamped `.pcap` files into `./pcaps/`.

---

## 3. Baseline Test (no loss)

From the Windows host, run the generator for a clean delivery:

```powershell
docker compose run --rm attacker `
    python /app/generator.py --case baseline --target 10.20.0.2:8080 --count 3
```

Observe in another terminal:

```powershell
docker compose logs -f backend
```

You should see the HTTP-like request arrive exactly once per connection, with the exact bytes you sent.

While the test runs, a new pcap is being written by the middle.

After the run, list captures:

```powershell
Get-ChildItem pcaps
```

Pick the most recent `.pcap` and (optionally) feed it to Zeek for the detailed retrans/reassembly log:

```powershell
# Requires the zeek profile (pulls the image the first time)
docker compose --profile zeek run --rm zeek `
    zeek -C -r /pcaps/capture-*.pcap /zeek-config/local.zeek
```

Look for `TCP_CONTENTS`, `CONN_EST`, `CONN_END` lines. No `TCP_REXMIT` should appear in a clean baseline.

You can also open the pcap in Wireshark on the Windows host and filter `tcp.analysis.retransmission` — it should be empty.

---

## 4. Loss-Induced Retransmission Test (first interesting case)

This is the first case that exercises real TCP retransmissions on the wire.

```powershell
docker compose run --rm attacker `
    python /app/generator.py --case loss --loss 8 --delay 10 --target 10.20.0.2:8080 --count 5
```

- The generator applies `tc qdisc ... netem loss 8% delay 10ms` on its `eth0`.
- The Linux TCP stack in the attacker container will experience loss and perform retransmissions (identical payload, new segments on the wire after RTO or fast retransmit).
- The middle captures every original transmission + every retransmission.
- The backend still receives exactly one copy of the data (the successful final delivery).

After the run:

1. Check backend logs — you should still see the full correct payload delivered (no corruption).
2. Take the newest pcap and open it in Wireshark:
   - Look for packets with the black "Retransmission" label or the `tcp.analysis.retransmission` filter.
   - You should see one or more retransmitted segments with the same seq/ack and same payload.
3. Run the Zeek analysis on that pcap:

   ```powershell
   docker compose --profile zeek run --rm zeek `
       zeek -C -r /pcaps/capture-2025... .pcap /zeek-config/local.zeek | Select-String -Pattern "REXMIT|CONTENTS|WEIRD"
   ```

   You will see `TCP_REXMIT` lines for the retransmitted segments and the corresponding `TCP_CONTENTS` that Zeek delivered after reassembly.

---

## 5. Inspecting a Capture (common commands)

From Windows host (after a test run):

```powershell
# Latest pcap
$pcap = (Get-ChildItem pcaps\*.pcap | Sort LastWriteTime -Descending | Select -First 1).FullName
Write-Host "Using $pcap"

# Quick stats with tshark (if you have it on Windows) or inside a container
docker compose --profile zeek run --rm zeek tshark -r /pcaps/$(Split-Path $pcap -Leaf) -q -z io,stat,1

# Zeek full transcript
docker compose --profile zeek run --rm zeek `
    zeek -C -r /pcaps/$(Split-Path $pcap -Leaf) /zeek-config/local.zeek > zeek-output.txt
```

Inside the middle container you can also add extra netem on the fly:

```powershell
docker compose exec middle tc qdisc show
docker compose exec middle tc qdisc add dev eth1 root netem loss 15%   # right leg, for example
```

Remember to delete the qdisc when done:

```powershell
docker compose exec middle tc qdisc del dev eth1 root
```

---

## 6. Cleaning Up Between Runs

```powershell
# Stop everything
docker compose down

# Or just the containers, keep volumes/networks
docker compose down --remove-orphans

# Delete old pcaps if you want a clean slate
Remove-Item pcaps\* -Force
```

---

## 7. Next Steps / Extending the Lab (per plan.txt)

- **Phase 2 (raw injection)**: Extend `generator.py` with a raw-socket mode + local iptables drop of the kernel flow so we can send *different* payloads on "retransmitted" seq numbers (overlapping desync).
- Add more interesting payloads (double-encoded, charset tricks, etc.).
- Add an automated `analyze.py` that parses the Zeek `conn.log` + `weird.log` + backend logs and flags any desync (bytes delivered to app vs what Zeek logged for the same UID).
- Bring Suricata into the picture (another service + pcap or live).
- Document any real bugs found in Zeek/Suricata reassembly and open coordinated disclosure issues.

---

## 8. Troubleshooting

- **No traffic in pcap**: Check that the generator actually connected (`docker compose logs attacker`). Verify routes inside containers:
  ```powershell
  docker compose exec attacker ip route
  docker compose exec backend  ip route
  ```
  Both should show default via `10.10.0.1` / `10.20.0.1` respectively.

- **Permission errors on raw/tc**: The containers run as root and have the correct capabilities. If you still get EPERM, ensure Docker Desktop has "Expose daemon on tcp://localhost:2375 without TLS" or just use the normal socket.

- **Zeek complains about events**: The `local.zeek` may need small adjustments for the exact Zeek 6.x event prototypes. Run with `-b` (bare) + explicit `@load` or look at `zeek -NN | grep -i tcp` inside the container for the current signatures.

- **Windows file permissions on bind mounts**: If the container cannot write to `./pcaps`, grant write access or move the volume to a Docker-managed named volume.

---

This runbook + the `docker-compose.yml` + the three service images gives you a fully reproducible, isolated environment for the first research question in the plan:

> Do Zeek (and later Suricata) exhibit asymmetric behavior between original and retransmitted TCP segments during reassembly?

Happy (defensive) hunting!
