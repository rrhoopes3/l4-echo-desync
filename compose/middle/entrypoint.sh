#!/bin/bash
# TRS Lab Middlebox — L3 router + always-on per-leg capture.
#
# Captures on each leg separately (Ethernet frames, not SLL) so the resulting
# pcaps replay cleanly into Suricata / ModSecurity / Wireshark / tshark.
#
# Helper scripts (callable via `docker compose exec middle ...`):
#   /usr/local/bin/impair-right   loss|drop|delay|clear  [args...]
#   /usr/local/bin/impair-left    loss|drop|delay|clear  [args...]
#
# Examples:
#   docker compose exec middle impair-right loss 8 10        # netem loss 8% delay 10ms on middle->backend
#   docker compose exec middle impair-right drop every 5     # iptables: drop every 5th packet (deterministic)
#   docker compose exec middle impair-right clear            # remove all impairments

set -euo pipefail

LEFT_NET=10.10.0.0/24
RIGHT_NET=10.20.0.0/24

# === Identify which interface is which leg by IP ===
# Docker assigns eth0/eth1 in alphabetical network-name order, but we don't
# want to depend on that — detect by configured address.
detect_iface() {
    local cidr=$1
    ip -o -4 addr show | awk -v cidr="$cidr" '
        {
            split($4, a, "/")
            ip=a[1]; bits=a[2]
            # naive subnet test: just match the /24 prefix
            split(cidr, b, "/")
            split(b[1], c, ".")
            prefix=c[1] "." c[2] "." c[3] "."
            if (ip ~ "^" prefix) { print $2; exit }
        }
    '
}

LEFT_IF=$(detect_iface "$LEFT_NET")
RIGHT_IF=$(detect_iface "$RIGHT_NET")

if [[ -z "$LEFT_IF" || -z "$RIGHT_IF" ]]; then
    echo "FATAL: could not detect interfaces (left=$LEFT_IF right=$RIGHT_IF)"
    ip addr
    exit 1
fi

echo "=== TRS Lab Middlebox starting ==="
echo "Left leg  (attacker, $LEFT_NET):  $LEFT_IF"
echo "Right leg (backend,  $RIGHT_NET): $RIGHT_IF"
echo "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

mkdir -p /pcaps

# === Write helper scripts ===
cat > /usr/local/bin/_impair <<'IMPAIR'
#!/bin/bash
# Usage: _impair <iface> <action> [args]
set -euo pipefail
IFACE=$1; ACTION=$2; shift 2 || true

case "$ACTION" in
  loss)
    # loss <pct> [delay_ms] — random loss via netem (egress on this iface)
    PCT=${1:-5}; DELAY=${2:-0}
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    if [[ "$DELAY" -gt 0 ]]; then
        tc qdisc add dev "$IFACE" root netem loss "${PCT}%" delay "${DELAY}ms"
    else
        tc qdisc add dev "$IFACE" root netem loss "${PCT}%"
    fi
    echo "Applied netem on $IFACE: loss=${PCT}% delay=${DELAY}ms"
    ;;

  drop)
    # drop every N — deterministic packet drop on egress via iptables statistic match
    # Usage: drop every <N>
    if [[ "${1:-}" != "every" ]]; then
        echo "Usage: impair-... drop every <N>"; exit 2
    fi
    N=${2:-5}
    # Use OUTPUT chain because forwarded packets pass FORWARD, and we want
    # to drop on the egress leg. Use FORWARD with outbound-iface match.
    iptables -D FORWARD -o "$IFACE" -p tcp -m statistic --mode nth --every "$N" --packet 0 -j DROP 2>/dev/null || true
    iptables -A FORWARD -o "$IFACE" -p tcp -m statistic --mode nth --every "$N" --packet 0 -j DROP
    echo "Applied deterministic drop on $IFACE: every $N TCP packets"
    ;;

  delay)
    # delay <ms> [jitter_ms]
    MS=${1:-50}; JITTER=${2:-0}
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    if [[ "$JITTER" -gt 0 ]]; then
        tc qdisc add dev "$IFACE" root netem delay "${MS}ms" "${JITTER}ms"
    else
        tc qdisc add dev "$IFACE" root netem delay "${MS}ms"
    fi
    echo "Applied netem on $IFACE: delay=${MS}ms jitter=${JITTER}ms"
    ;;

  clear)
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    # Remove our iptables drop rules for this iface
    while iptables -D FORWARD -o "$IFACE" -p tcp -m statistic --mode nth --every 5 --packet 0 -j DROP 2>/dev/null; do :; done
    for n in 2 3 4 5 6 7 8 9 10 20 50 100; do
        while iptables -D FORWARD -o "$IFACE" -p tcp -m statistic --mode nth --every "$n" --packet 0 -j DROP 2>/dev/null; do :; done
    done
    echo "Cleared impairments on $IFACE"
    ;;

  show)
    echo "--- tc qdisc on $IFACE ---"
    tc qdisc show dev "$IFACE"
    echo "--- iptables FORWARD rules touching $IFACE ---"
    iptables -L FORWARD -n -v | grep -E "$IFACE|Chain" || true
    ;;

  *)
    echo "Unknown action: $ACTION (use loss|drop|delay|clear|show)"; exit 2
    ;;
esac
IMPAIR
chmod +x /usr/local/bin/_impair

cat > /usr/local/bin/impair-left <<EOF
#!/bin/bash
exec /usr/local/bin/_impair "$LEFT_IF" "\$@"
EOF
cat > /usr/local/bin/impair-right <<EOF
#!/bin/bash
exec /usr/local/bin/_impair "$RIGHT_IF" "\$@"
EOF
chmod +x /usr/local/bin/impair-left /usr/local/bin/impair-right

# === Per-leg rolling capture (Ethernet frames, no SLL) ===
# -G 300 = rotate every 5 min, -W 12 = keep 12 files per leg (1h ring)
# -s 0   = full packets, -nn = no name resolution
TS=$(date +%Y%m%d-%H%M%S)
echo "Starting per-leg captures..."
tcpdump -i "$LEFT_IF"  -s 0 -nn -G 300 -W 12 -w "/pcaps/left-${TS}-%Y%m%d-%H%M%S.pcap"  >/tmp/tcpdump-left.log  2>&1 &
LEFT_PID=$!
tcpdump -i "$RIGHT_IF" -s 0 -nn -G 300 -W 12 -w "/pcaps/right-${TS}-%Y%m%d-%H%M%S.pcap" >/tmp/tcpdump-right.log 2>&1 &
RIGHT_PID=$!

echo "tcpdump PIDs: left=$LEFT_PID right=$RIGHT_PID"
echo "Captures rotate every 5 min, keeping 12 files per leg (~1h ring)."
echo "Files land in /pcaps/ (bind-mounted to ./pcaps on the host)."

cleanup() {
    echo "Stopping captures..."
    kill "$LEFT_PID" "$RIGHT_PID" 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM EXIT

if [ $# -gt 0 ]; then
    exec "$@"
else
    tail -f /dev/null &
    wait $!
fi
