# Network-Intrusion-Detection-System
Network-based intrusion detection system using Suricata.
# Network Intrusion Detection System (Suricata)

A network-based IDS built with Suricata. It monitors traffic continuously, detects suspicious activity using custom rules, blocks attackers automatically and shows the results on a dashboard.

## Components
| File | Purpose |
|---|---|
| local.rules | Custom Suricata detection rules |
| ids_response.py | Reads alerts and blocks attacker IPs with iptables for 60 seconds |
| plot_alerts.py | Creates a dashboard chart (alerts_dashboard.png) from eve.json |

## Detection Rules
| SID | Detects |
|---|---|
| 1000001 | ICMP ping |
| 1000002 | Port scan (15+ SYN packets in 5 seconds) |
| 1000003 | SQL injection (UNION SELECT in HTTP request) |
| 1000004 | SSH brute force (5+ connection attempts in 60 seconds) |

Emerging Threats Open rules are also loaded with suricata-update.

## Requirements
Ubuntu, Suricata, nmap (for testing), Python 3 with matplotlib, root privileges.

## How to Run
1. Start monitoring:
       sudo suricata -c /etc/suricata/suricata.yaml -i wlp0s20f3 -i lo -k none
2. Watch alerts:
       sudo tail -f /var/log/suricata/fast.log
3. Start the response system:
       sudo python3 ids_response.py
4. Generate the dashboard:
       sudo python3 plot_alerts.py

## Testing (own machine only)
    ping -c 3 192.168.100.14
    sudo nmap -sS -p 1-1000 192.168.100.14

## Results
Alerts are written to /var/log/suricata/fast.log and eve.json. Blocked IPs are recorded in blocked_ips.log and removed automatically after 60 seconds.

## Note
Use only on systems you own or have permission to test.
EOF
