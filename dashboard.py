import matplotlib.pyplot as plt
import matplotlib.animation as animation
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP
from collections import defaultdict
import datetime

# Data stores
ip_packet_count = defaultdict(int)
protocol_count = defaultdict(int)
timestamps = []
packet_rates = []
packet_count_total = 0
warnings = []

def detect_anomaly(packet):
    global packet_count_total
    if IP in packet:
        src_ip = packet[IP].src
        ip_packet_count[src_ip] += 1
        packet_count_total += 1

        if TCP in packet:
            protocol_count['TCP'] += 1
        elif UDP in packet:
            protocol_count['UDP'] += 1
        elif ICMP in packet:
            protocol_count['ICMP'] += 1
        elif DNS in packet:
            protocol_count['DNS'] += 1
        else:
            protocol_count['OTHER'] += 1

        if DNS in packet and DNSQR in packet:
            dns_query = packet[DNSQR].qname.decode('utf-8')
            suspicious_keywords = ['malware', 'botnet', 'phishing', 'hack', 'exploit']
            for keyword in suspicious_keywords:
                if keyword in dns_query.lower():
                    warnings.append(f"SUSPICIOUS DNS: {dns_query}")

# Setup figure
fig, axes = plt.subplots(2, 2, figsize=(14, 8))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('ARGUS - Network Anomaly Detector', color='#00ff99', fontsize=16, fontweight='bold')

for ax in axes.flat:
    ax.set_facecolor('#111111')
    ax.tick_params(colors='#00ff99')
    ax.spines['bottom'].set_color('#00ff99')
    ax.spines['top'].set_color('#00ff99')
    ax.spines['left'].set_color('#00ff99')
    ax.spines['right'].set_color('#00ff99')

def update(frame):
    # Clear all plots
    for ax in axes.flat:
        ax.cla()
        ax.set_facecolor('#111111')
        ax.tick_params(colors='#00ff99')
        for spine in ax.spines.values():
            spine.set_color('#00ff99')

    # Plot 1 - Top IPs by packet count
    ax1 = axes[0, 0]
    if ip_packet_count:
        top_ips = sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True)[:5]
        ips = [x[0] for x in top_ips]
        counts = [x[1] for x in top_ips]
        bars = ax1.barh(ips, counts, color='#00ff99')
        ax1.set_title('Top 5 IPs by Traffic', color='#00ff99')
        ax1.set_xlabel('Packet Count', color='#00ff99')

    # Plot 2 - Protocol distribution
    ax2 = axes[0, 1]
    if protocol_count:
        labels = list(protocol_count.keys())
        sizes = list(protocol_count.values())
        colors = ['#00ff99', '#00cc77', '#009955', '#006633', '#003311']
        ax2.pie(sizes, labels=labels, colors=colors[:len(labels)],
                textprops={'color': '#00ff99'}, autopct='%1.1f%%')
        ax2.set_title('Protocol Distribution', color='#00ff99')

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

# Start sniffing in background
import threading
sniff_thread = threading.Thread(
    target=lambda: sniff(prn=detect_anomaly, store=0, filter="ip or udp port 53")
)
sniff_thread.daemon = True
sniff_thread.start()

# Start dashboard
ani = animation.FuncAnimation(fig, update, interval=2000)
plt.show()