from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            proto_name = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto_name = "UDP"
            dst_port = packet[UDP].dport
        else:
            proto_name = "IGMP"
            dst_port = 0

        print(f"[{proto_name}] {src_ip} → {dst_ip} : Port {dst_port}")

print("Starting packet capture... Press Ctrl+C to stop")
sniff(prn=packet_callback, store=0, count=100, filter="ip")