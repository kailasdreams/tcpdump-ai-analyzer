"""
pcap_parser.py  –  Pure-Python PCAP reader using dpkt.
Used as fallback when tcpdump is not installed or fails.
Produces output in the same human-readable style as tcpdump -nn -v.
"""
import socket
import struct
import datetime
from collections import defaultdict

METHOD_LABEL = "Python dpkt parser (tcpdump fallback)"


def _safe_ip(addr: bytes) -> str:
    try:
        return socket.inet_ntoa(addr)
    except Exception:
        return addr.hex()


def _proto_name(proto: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP", 89: "OSPF"}.get(proto, str(proto))


def _tcp_flags(flags: int) -> str:
    names = [(0x02, "S"), (0x12, "SA"), (0x10, "A"), (0x04, "R"),
             (0x01, "F"), (0x08, "P"), (0x20, "U")]
    result = []
    if flags & 0x02: result.append("S")
    if flags & 0x01: result.append("F")
    if flags & 0x04: result.append("R")
    if flags & 0x08: result.append("P")
    if flags & 0x10: result.append("A")
    if flags & 0x20: result.append("U")
    return "".join(result) if result else "."


def parse_pcap_with_dpkt(filepath: str) -> tuple[str, str]:
    """
    Parse a PCAP file and return (text_summary, method_label).
    Raises ImportError if dpkt is missing.
    """
    try:
        import dpkt
    except ImportError:
        return (
            "[ERROR] dpkt not installed. Run: pip install dpkt",
            METHOD_LABEL,
        )

    lines = []
    stats = defaultdict(int)
    conversations = defaultdict(lambda: {"pkts": 0, "bytes": 0, "flags": set()})
    errors = []
    total = 0

    try:
        with open(filepath, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
                link_type = pcap.datalink()
            except Exception as e:
                return f"[ERROR] Cannot open PCAP: {e}", METHOD_LABEL

            for ts, buf in pcap:
                total += 1
                ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S.%f")

                try:
                    # Ethernet
                    if link_type == dpkt.pcap.DLT_EN10MB:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            stats["non-ip"] += 1
                            continue
                        ip = eth.data
                    # Raw IP (e.g. loopback on Linux)
                    elif link_type == dpkt.pcap.DLT_RAW:
                        ip = dpkt.ip.IP(buf)
                    # Null/loopback (macOS)
                    elif link_type == dpkt.pcap.DLT_NULL:
                        family = struct.unpack("<I", buf[:4])[0]
                        ip = dpkt.ip.IP(buf[4:])
                    else:
                        stats["unknown-link"] += 1
                        continue

                    src_ip = _safe_ip(ip.src)
                    dst_ip = _safe_ip(ip.dst)
                    proto  = ip.p
                    pname  = _proto_name(proto)
                    plen   = ip.len
                    stats[pname] += 1

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp   = ip.data
                        flags = _tcp_flags(tcp.flags)
                        sport = tcp.sport
                        dport = tcp.dport
                        seq   = tcp.seq
                        ack   = tcp.ack
                        win   = tcp.win
                        key   = (src_ip, sport, dst_ip, dport)
                        conversations[key]["pkts"]  += 1
                        conversations[key]["bytes"] += plen
                        conversations[key]["flags"].add(flags)
                        line = (f"{ts_str} IP {src_ip}:{sport} > {dst_ip}:{dport} "
                                f"Flags [{flags}] seq {seq} ack {ack} win {win} length {plen}")

                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp   = ip.data
                        sport = udp.sport
                        dport = udp.dport
                        key   = (src_ip, sport, dst_ip, dport)
                        conversations[key]["pkts"]  += 1
                        conversations[key]["bytes"] += plen
                        line = (f"{ts_str} IP {src_ip}:{sport} > {dst_ip}:{dport} "
                                f"UDP length {len(udp.data)}")

                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp  = ip.data
                        itype = icmp.type
                        icode = icmp.code
                        line  = (f"{ts_str} IP {src_ip} > {dst_ip} "
                                 f"ICMP type={itype} code={icode} length {plen}")

                    else:
                        line = (f"{ts_str} IP {src_ip} > {dst_ip} "
                                f"proto={pname} length {plen}")

                    lines.append(line)

                except Exception as pkt_err:
                    errors.append(f"pkt#{total}: {pkt_err}")
                    stats["parse-errors"] += 1

    except FileNotFoundError:
        return f"[ERROR] File not found: {filepath}", METHOD_LABEL

    # ── Build summary header ──────────────────────────────────────────
    header = [
        f"=== PCAP Summary  ({filepath}) ===",
        f"Total packets : {total}",
        f"Protocol breakdown: { {k: v for k, v in stats.items()} }",
        "",
    ]

    # Top-10 conversations by byte volume
    if conversations:
        header.append("--- Top Conversations (by volume) ---")
        top = sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
        for (si, sp, di, dp), info in top:
            flags_str = "/".join(sorted(info["flags"]))
            header.append(
                f"  {si}:{sp} <-> {di}:{dp}  "
                f"pkts={info['pkts']}  bytes={info['bytes']}  flags=[{flags_str}]"
            )
        header.append("")

    # RST / SYN-only anomaly quick-scan
    rst_lines  = [l for l in lines if "[R"  in l]
    synack     = [l for l in lines if "[SA]" in l or "[S]" in l]
    anomalies  = []
    if rst_lines:
        anomalies.append(f"⚠  RST packets detected: {len(rst_lines)}")
    if not synack:
        anomalies.append("⚠  No SYN/SYN-ACK packets – may be mid-session capture")
    if anomalies:
        header.append("--- Anomaly Hints ---")
        header += anomalies
        header.append("")

    if errors:
        header.append(f"--- Parse warnings ({len(errors)} packets skipped) ---")
        header += errors[:10]
        header.append("")

    header.append("--- Packet Log ---")
    output = "\n".join(header) + "\n" + "\n".join(lines)
    return output, METHOD_LABEL
