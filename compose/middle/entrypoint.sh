#!/bin/bash
set -euo pipefail

echo "=== TRS Lab Middlebox (L3 router + capture) starting ==="
echo "Left (attacker):  10.10.0.1/24"
echo "Right (backend):  10.20.0.1/24"
echo "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

mkdir -p /pcaps

# Start a rolling capture that sees every packet the router forwards.
# -i any gives us all interfaces in one file (includes the two legs).
# We use -nn to avoid DNS and -s 0 for full packets.
CAPTURE_FILE="/pcaps/capture-$(date +%Y%m%d-%H%M%S).pcap"
echo "Starting tcpdump -> $CAPTURE_FILE"
tcpdump -i any -s 0 -nn -w "$CAPTURE_FILE" > /tmp/tcpdump.log 2>&1 &
TCPDUMP_PID=$!

echo "tcpdump PID: $TCPDUMP_PID"
echo "Capture will continue until container stops."

# Optional: allow easy addition of netem from outside via docker compose exec
# e.g. tc qdisc add dev eth1 root netem loss 5% delay 20ms
# eth0 = left (10.10), eth1 = right (10.20) typically

# Keep the container alive forever (or until killed)
trap 'echo "Stopping capture..."; kill $TCPDUMP_PID 2>/dev/null || true; exit 0' INT TERM EXIT

# If someone passes extra args, exec them; otherwise just sleep
if [ $# -gt 0 ]; then
    exec "$@"
else
    # Sleep in background so trap works reliably
    tail -f /dev/null &
    wait $!
fi
