# TRS Research - Zeek local.zeek
# Verbose TCP reassembly + retransmission logging for desync detection
#
# Usage (offline pcap):
#   zeek -C -r /pcaps/capture-....pcap /zeek-config/local.zeek
#
# The goal is to expose exactly what Zeek's TCP reassembly engine saw for each
# segment / retransmitted segment and compare it to what the backend application received.

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/weird

# === TCP Reassembly tuning for research ===
redef TCP::reassemble_all_packets = T;          # Do not elide any segments
redef TCP::max_gaps = 100;                      # Be tolerant but log gaps
redef TCP::max_old_segments = 100;              # Keep history of older segments

# Produce the classic conn.log + http.log + weird.log with maximum detail
redef Conn::default_extract_max_size = 0;       # no automatic file extraction unless wanted

# Log every TCP contents chunk that the reassembler delivers to the application layer
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    # This event fires for reassembled *application* data (after reassembly)
    # Very useful to see what Zeek believed the stream contained at each point.
    local dir = is_orig ? "->" : "<-";
    print fmt("TCP_CONTENTS %s %s seq=%d len=%d | %s",
              c$uid, dir, seq, |contents|, contents[:120]);
    }

# Log retransmissions explicitly (Zeek raises this when it detects a retransmit)
event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count)
    {
    local dir = is_orig ? "->" : "<-";
    print fmt("TCP_REXMIT  %s %s seq=%d len=%d in_flight=%d",
              c$uid, dir, seq, len, data_in_flight);
    NOTICE([$note=Recon::TCP_Retransmission,
            $msg=fmt("Retransmission observed: %s %s seq=%d", c$uid, dir, seq),
            $conn=c]);
    }

# Also catch "weird" events that often flag reassembly anomalies
event weird(c: connection, name: string, addl: string, source: string)
    {
    if ( /reassem|tcp|gap|overlap/ in name )
        print fmt("WEIRD %s %s %s %s", c$uid, name, addl, source);
    }

# Extra: log the initial SYN/FIN/ACK flags with seq numbers for the flow
event connection_established(c: connection)
    {
    print fmt("CONN_EST %s orig=%s:%d resp=%s:%d orig_seq=%d resp_seq=%d",
              c$uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p,
              c$orig$start_seq, c$resp$start_seq);
    }

event connection_state_remove(c: connection)
    {
    print fmt("CONN_END  %s duration=%.3fs orig_bytes=%d resp_bytes=%d",
              c$uid, c$duration, c$orig$size, c$resp$size);
    }

# If you want per-segment visibility (very verbose, before full reassembly):
# event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
#     { ... }

print "TRS Zeek configuration loaded - retransmit and reassembly events will be printed.";