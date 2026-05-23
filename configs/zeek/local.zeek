# TRS Research - Zeek local.zeek
# Verbose TCP reassembly + retransmission logging for desync detection.
#
# Usage (offline pcap):
#   zeek -C -r /pcaps/eth0-XXXX.pcap /zeek-config/local.zeek
#
# Goal: expose exactly what Zeek's TCP reassembly engine saw for each segment
# (incl. retransmits) and compare it to what the backend application received.

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/weird

# === Notice type for retransmit observations ===
redef enum Notice::Type += {
    TCP_Retransmission,
    TCP_Overlap_Different_Content,
};

# === Reassembly tuning ===
# Note: there is no "reassemble_all_packets" tunable in Zeek 6.x.
# The exact names of the per-flow reassembly knobs vary between Zeek
# versions; for portability we leave them at defaults and observe via events.
# If you need to retain more out-of-order history, uncomment after verifying
# the spelling on your Zeek build with `zeek -NN | grep -i reassem`.
# redef tcp_max_old_segments = 1024;

# === Reassembled application-layer chunks ===
# tcp_contents fires per chunk the reassembler delivers up to scriptland.
# Compare these against the backend's "APPLICATION VIEW" hexdump.
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    local dir = is_orig ? "C->S" : "S->C";
    print fmt("TCP_CONTENTS uid=%s %s seq=%d len=%d preview=%s",
              c$uid, dir, seq, |contents|, contents[:120]);
    }

# === Retransmits ===
# Zeek raises tcp_rexmit on detected duplicate-seq segments. Signature is
# (c, is_orig, seq, len, data_in_flight) on Zeek 5.x/6.x.
event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count)
    {
    local dir = is_orig ? "C->S" : "S->C";
    print fmt("TCP_REXMIT uid=%s %s seq=%d len=%d in_flight=%d",
              c$uid, dir, seq, len, data_in_flight);
    NOTICE([$note=TCP_Retransmission,
            $msg=fmt("Retransmission observed: %s %s seq=%d len=%d",
                     c$uid, dir, seq, len),
            $conn=c]);
    }

# === Weird events related to reassembly ===
# Catches: data_after_reset, fragment_with_DF, rexmit_inconsistency,
#          retransmission_inconsistency, possible_split_routing, etc.
event conn_weird(name: string, c: connection, addl: string)
    {
    if ( /rexmit|retrans|reassem|overlap|gap|inconsist/ in name )
        print fmt("TCP_WEIRD uid=%s name=%s addl=%s", c$uid, name, addl);
    }

# === Connection lifecycle ===
event connection_established(c: connection)
    {
    print fmt("CONN_EST uid=%s %s:%d -> %s:%d",
              c$uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }

event connection_state_remove(c: connection)
    {
    local state = c?$conn && c$conn?$conn_state ? c$conn$conn_state : "?";
    print fmt("CONN_END uid=%s duration=%.3fs orig_bytes=%d resp_bytes=%d state=%s",
              c$uid, interval_to_double(c$duration),
              c$orig$size, c$resp$size, state);
    }

print "TRS Zeek configuration loaded.";
print "Will print: CONN_EST, TCP_CONTENTS, TCP_REXMIT, TCP_WEIRD, CONN_END";
