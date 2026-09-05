from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP
from collections import defaultdict
import datetime

# Store packet counts per IP
ip_packet_count = defaultdict(int)
port_scan_tracker = defaultdict(set)

# Thresholds
PACKET_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 10

# Log file setup
log_file = open("alerts.log", "a", encoding="utf-8")

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    log_file.write(full_message + "\n")
    log_file.flush()

def detect_anomaly(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        ip_packet_count[src_ip] += 1

        # Protocol detection
        if TCP in packet:
            dst_port = packet[TCP].dport
            proto = "TCP"
            port_scan_tracker[src_ip].add(dst_port)

            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                log(f"[WARNING] PORT SCAN DETECTED from {src_ip} - {len(port_scan_tracker[src_ip])} ports scanned")

        elif UDP in packet:
            dst_port = packet[UDP].dport
            proto = "UDP"

        elif ICMP in packet:
            proto = "ICMP"
            dst_port = 0

        elif DNS in packet:
            proto = "DNS"
            dst_port = 53

        else:
            proto_num = packet[IP].proto
            proto = {
                1: "ICMP",
                2: "IGMP",
                6: "TCP",
                17: "UDP",
                41: "IPv6",
                47: "GRE",
                50: "ESP",
                51: "AH",
                89: "OSPF",
                132: "SCTP"
            }.get(proto_num, f"PROTO-{proto_num}")
            dst_port = 0

        # High traffic detection
        if ip_packet_count[src_ip] > PACKET_THRESHOLD:
            log(f"[WARNING] HIGH TRAFFIC DETECTED from {src_ip} - {ip_packet_count[src_ip]} packets")

        # DNS monitoring
        if DNS in packet and DNSQR in packet:
            dns_query = packet[DNSQR].qname.decode('utf-8')
            suspicious_keywords = [
                'malware', 'botnet', 'phishing', 'hack',
                'exploit', 'payload', 'c2', 'command'
            ]
            log(f"[DNS] {src_ip} queried -> {dns_query}")
            for keyword in suspicious_keywords:
                if keyword in dns_query.lower():
                    log(f"[WARNING] SUSPICIOUS DNS QUERY from {src_ip} -> {dns_query}")
                    break

        log(f"[{proto}] {src_ip} -> {dst_ip} : Port {dst_port}")

log(">>> Argus - Network Anomaly Detector Started")
log("-" * 60)

try:
    sniff(prn=detect_anomaly, store=0, filter="ip or udp port 53")
except KeyboardInterrupt:
    log(">>> Detector stopped by user")
    log_file.close()