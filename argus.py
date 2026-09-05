from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP
from collections import defaultdict
import datetime
import threading
import requests
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import geoip2.database


# ─── Configuration ─────────────────────────────────────────
PACKET_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 10
ABUSEIPDB_API_KEY = "1ed76d3b1f6b4c5b8499b2a32998bd8b6fb8bf10d2ff4535ecb6d29b59bddf43fa83d6f34b6d9981"

# ─── Data Stores ───────────────────────────────────────────
ip_packet_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
protocol_count = defaultdict(int)
country_count = defaultdict(int)
timestamps = []
packet_rates = []
packet_count_total = 0
warnings = []
checked_ips = set()

# ─── Log File ──────────────────────────────────────────────
log_file = open("alerts.log", "a", encoding="utf-8")

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    log_file.write(full_message + "\n")
    log_file.flush()

# ─── GeoIP Setup ───────────────────────────────────────────
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    GEO_ENABLED = True
    log(">>> GeoIP database loaded successfully")
except Exception:
    GEO_ENABLED = False
    log(">>> GeoIP database not found - geolocation disabled")

def get_location(ip):
    if not GEO_ENABLED:
        return "Unknown"
    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("127."):
        return "Local"
    try:
        response = geo_reader.city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or ""
        country_count[country] += 1
        return f"{city}, {country}" if city else country
    except Exception:
        return "Unknown"

# ─── Blacklist Check ───────────────────────────────────────
def check_blacklist(ip):
    if not ip:
        return
    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("127."):
        return
    if ip in checked_ips:
        return

    checked_ips.add(ip)

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=3
        )

        data = response.json()
        abuse_score = data['data']['abuseConfidenceScore']
        country = data['data']['countryCode']
        total_reports = data['data']['totalReports']

        if abuse_score > 25:
            msg = f"[BLACKLIST] MALICIOUS IP {ip} | Score: {abuse_score}% | Country: {country} | Reports: {total_reports}"
            log(msg)
            warnings.append(msg)
        else:
            log(f"[CLEAN] {ip} | Score: {abuse_score}% | Country: {country}")

    except Exception:
        pass

# ─── Packet Handler ────────────────────────────────────────
def detect_anomaly(packet):
    global packet_count_total

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Blacklist check in background
        threading.Thread(target=check_blacklist, args=(src_ip,), daemon=True).start()
        threading.Thread(target=check_blacklist, args=(dst_ip,), daemon=True).start()

        ip_packet_count[src_ip] += 1
        packet_count_total += 1

        # Protocol detection
        if TCP in packet:
            dst_port = packet[TCP].dport
            proto = "TCP"
            protocol_count['TCP'] += 1
            port_scan_tracker[src_ip].add(dst_port)

            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                msg = f"[WARNING] PORT SCAN DETECTED from {src_ip} - {len(port_scan_tracker[src_ip])} ports scanned"
                log(msg)
                warnings.append(msg)

        elif UDP in packet:
            dst_port = packet[UDP].dport
            proto = "UDP"
            protocol_count['UDP'] += 1

        elif ICMP in packet:
            proto = "ICMP"
            dst_port = 0
            protocol_count['ICMP'] += 1

        elif DNS in packet:
            proto = "DNS"
            dst_port = 53
            protocol_count['DNS'] += 1

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
            protocol_count[proto] += 1

        # High traffic detection
        if ip_packet_count[src_ip] > PACKET_THRESHOLD:
            msg = f"[WARNING] HIGH TRAFFIC DETECTED from {src_ip} - {ip_packet_count[src_ip]} packets"
            log(msg)
            warnings.append(msg)

        # DNS monitoring
        if DNS in packet and DNSQR in packet:
            try:
                dns_query = packet[DNSQR].qname.decode('utf-8')
                suspicious_keywords = [
                    'malware', 'botnet', 'phishing',
                    'hack', 'exploit', 'payload', 'c2', 'command'
                ]
                log(f"[DNS] {src_ip} queried -> {dns_query}")
                for keyword in suspicious_keywords:
                    if keyword in dns_query.lower():
                        msg = f"[WARNING] SUSPICIOUS DNS QUERY from {src_ip} -> {dns_query}"
                        log(msg)
                        warnings.append(msg)
                        break
            except Exception:
                pass

        # Log with geolocation
        src_location = get_location(src_ip)
        dst_location = get_location(dst_ip)
        log(f"[{proto}] {src_ip} ({src_location}) -> {dst_ip} ({dst_location}) : Port {dst_port}")

# ─── Dashboard Setup ───────────────────────────────────────
fig, axes = plt.subplots(2, 2, figsize=(14, 8))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('ARGUS - Network Anomaly Detector', color='#00ff99', fontsize=16, fontweight='bold')

for ax in axes.flat:
    ax.set_facecolor('#111111')
    ax.tick_params(colors='#00ff99')
    for spine in ax.spines.values():
        spine.set_color('#00ff99')

def update(frame):
    for ax in axes.flat:
        ax.cla()
        ax.set_facecolor('#111111')
        ax.tick_params(colors='#00ff99')
        for spine in ax.spines.values():
            spine.set_color('#00ff99')

    # Plot 1 - Top IPs
    ax1 = axes[0, 0]
    if ip_packet_count:
        top_ips = sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True)[:5]
        ips = [x[0] for x in top_ips]
        counts = [x[1] for x in top_ips]
        ax1.barh(ips, counts, color='#00ff99')
        ax1.set_title('Top 5 IPs by Traffic', color='#00ff99')
        ax1.set_xlabel('Packet Count', color='#00ff99')

    # Plot 2 - Top Countries
    ax2 = axes[0, 1]
    if country_count:
        top_countries = sorted(country_count.items(), key=lambda x: x[1], reverse=True)[:5]
        countries = [x[0] for x in top_countries]
        counts = [x[1] for x in top_countries]
        ax2.barh(countries, counts, color='#00cc77')
        ax2.set_title('Top 5 Countries by Traffic', color='#00ff99')
        ax2.set_xlabel('Packet Count', color='#00ff99')
    else:
        ax2.set_title('Top 5 Countries by Traffic', color='#00ff99')
        ax2.text(0.3, 0.5, 'Collecting data...', color='#00ff99',
                transform=ax2.transAxes)

    # Plot 3 - Packet rate over time
    ax3 = axes[1, 0]
    timestamps.append(datetime.datetime.now().strftime("%H:%M:%S"))
    packet_rates.append(packet_count_total)
    if len(timestamps) > 20:
        timestamps.pop(0)
        packet_rates.pop(0)
    ax3.plot(timestamps, packet_rates, color='#00ff99', linewidth=2)
    ax3.set_title('Total Packets Over Time', color='#00ff99')
    ax3.set_xlabel('Time', color='#00ff99')
    ax3.set_ylabel('Packets', color='#00ff99')
    plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Plot 4 - Warnings
    ax4 = axes[1, 1]
    ax4.set_title('Warnings', color='#ff0000')
    ax4.axis('off')
    if warnings:
        warning_text = '\n'.join(warnings[-5:])
        ax4.text(0.1, 0.5, warning_text, color='#ff0000',
                fontsize=9, verticalalignment='center',
                transform=ax4.transAxes, wrap=True)
    else:
        ax4.text(0.3, 0.5, 'No warnings detected',
                color='#00ff99', fontsize=12,
                verticalalignment='center',
                transform=ax4.transAxes)

    plt.tight_layout()

# ─── Start Sniffer Thread ──────────────────────────────────
sniff_thread = threading.Thread(
    target=lambda: sniff(prn=detect_anomaly, store=0, filter="ip or udp port 53")
)
sniff_thread.daemon = True
sniff_thread.start()

# ─── Start ─────────────────────────────────────────────────
log(">>> ARGUS - Network Anomaly Detector Started")
log("-" * 60)

try:
    ani = animation.FuncAnimation(fig, update, interval=2000)
    plt.show()
except KeyboardInterrupt:
    log(">>> ARGUS stopped by user")
    log_file.close()