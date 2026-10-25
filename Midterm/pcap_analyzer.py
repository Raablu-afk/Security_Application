# Offline PCAP analysis (based on Lab 4 Traffic_sniffer.py / Anomaly_Detector.py)
from collections import Counter

from scapy.all import IP, TCP, UDP, rdpcap

SCAN_MIN_PORTS = 10      # one source sending SYNs to 10+ different ports = port scan
FLOOD_MIN_SYNS = 10      # 10+ unanswered SYNs to the same port = brute force / SYN flood
DNS_HEADER_SIZE = 12     # a real DNS message is at least 12 bytes long


def analyze_pcap(path):
    packets = rdpcap(path)

    tcp_count = 0
    udp_count = 0
    sources = Counter()
    dst_ports = Counter()
    syns = []                # (packet number, time, src, dst, sport, dport)
    answered = set()         # SYNs that got a SYN-ACK: (src, dst, sport, dport)
    bad_dns = []             # packet numbers of UDP/53 packets that are not DNS

    for i, pkt in enumerate(packets):
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        sources[src] += 1

        if TCP in pkt:
            tcp_count += 1
            flags = str(pkt[TCP].flags)
            if flags == "S":
                syns.append((i, float(pkt.time), src, dst, pkt[TCP].sport, pkt[TCP].dport))
                dst_ports["TCP " + str(pkt[TCP].dport)] += 1
            elif flags == "SA":
                # reply from server: swap direction to match the original SYN
                answered.add((dst, src, pkt[TCP].dport, pkt[TCP].sport))

        elif UDP in pkt:
            udp_count += 1
            dst_ports["UDP " + str(pkt[UDP].dport)] += 1
            if pkt[UDP].dport == 53 and len(bytes(pkt[UDP].payload)) < DNS_HEADER_SIZE:
                bad_dns.append(i)

    unanswered = [s for s in syns if (s[2], s[3], s[4], s[5]) not in answered]
    alerts = []

    # Detection 1: port scan (many different ports from one source)
    ports_by_src = {}
    for s in syns:
        ports_by_src.setdefault(s[2], []).append(s)
    for src, items in ports_by_src.items():
        ports = sorted(set(s[5] for s in items))
        if len(ports) >= SCAN_MIN_PORTS:
            span = items[-1][1] - items[0][1]
            alerts.append(f"PORT SCAN: {src} sent SYNs to {len(ports)} ports ({ports[0]}-{ports[-1]}) "
                          f"in {span:.2f} s, packets {items[0][0]}-{items[-1][0]}")

    # Detection 2: many unanswered SYNs to one port (SSH brute force / SYN flood)
    by_target = {}
    for s in unanswered:
        by_target.setdefault((s[2], s[3], s[5]), []).append(s)
    for (src, dst, port), items in by_target.items():
        if len(items) >= FLOOD_MIN_SYNS:
            span = items[-1][1] - items[0][1]
            alerts.append(f"SYN FLOOD / BRUTE FORCE: {src} sent {len(items)} unanswered SYNs to {dst}:{port} "
                          f"in {span:.2f} s, packets {items[0][0]}-{items[-1][0]}")

    # Detection 3: data on UDP port 53 that is too short to be DNS (possible tunnelling)
    if bad_dns:
        sample = bytes(packets[bad_dns[0]][UDP].payload)
        alerts.append(f"NON-DNS DATA ON PORT 53: {len(bad_dns)} packets (packets {bad_dns[0]}-{bad_dns[-1]}), "
                      f"payload {sample[:20]!r} is shorter than a {DNS_HEADER_SIZE}-byte DNS header")

    duration = float(packets[-1].time) - float(packets[0].time) if packets else 0
    summary = {
        "total_packets": len(packets),
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "duration_s": round(duration, 2),
        "top_sources": sources.most_common(5),
        "top_destination_ports": dst_ports.most_common(5),
        "syn_packets": len(syns),
        "syn_without_reply": len(unanswered),
    }
    return {"summary": summary, "alerts": alerts}


if __name__ == "__main__":
    import sys
    result = analyze_pcap(sys.argv[1])
    print(result["summary"])
    for alert in result["alerts"]:
        print("ALERT:", alert)
