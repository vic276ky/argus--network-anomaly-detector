I built ARGUS as a hands-on project to understand how network traffic behaves in real time and how suspicious activity can be identified. Instead of only studying intrusion detection theoretically, I wanted to build a tool that could actually monitor and analyse network traffic.

ARGUS captures live network packets, identifies protocols, and detects patterns such as port scans and unusually high traffic. It also monitors DNS requests for potentially suspicious domains and checks IP addresses against the AbuseIPDB threat intelligence API. I added IP geolocation to better understand where observed traffic was coming from.

The collected information is logged with timestamps and displayed on a live dashboard that updates every two seconds. The dashboard shows active IP addresses, traffic by country, packet rates, and security warnings.

I started with basic packet capture and gradually added features such as blacklist checking, geolocation, and threading. Working on these features helped me understand how network protocols behave, how normal traffic differs from suspicious activity, and some of the practical challenges involved in processing network data efficiently.

I named the project ARGUS, after the hundred-eyed giant from Greek mythology, as the project is designed to continuously monitor network activity from different angles.
