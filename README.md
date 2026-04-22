# Favour's Network Sniffer -- CodeAlpha Task

I built a tool that basically captures live network traffic and breaks it down for you. You can see the source/destination IP addresses, the ports, and what protocol is running (TCP/UDP).
I added colours to make it easier to read at a glance.


## What This Tool Does

- Captures live network packets with timestamps from your computer's network interface
- Analyzes packet structure across OSI model layers (Ethernet, IP, TCP/UDP)
- Shows detailed information: source/destination IPs, port numbers, protocols
- Identifies network services: HTTP, HTTPS, SSH, DNS, FTP, and more
- Coloured terminal output for easy reading
- Shows packet payloads: Raw data in hexadecimal and ASCII format (first 50 bytes)
- Exports to industry standard: Saves captures as PCAP files for Wireshark
- Tracks statistics: Counts TCP, UDP, and other protocol types
- Saves to log file (favour_capture_log.txt) for quick review and incident reporting
- Timestamps every packet so you know excatly when activity occurred


## What I Learned About Network Protocols
Before thhis, i thought when you visit a website, your computer just sends one big message. Now i know it actually breaks everything into small pieces called packets. Each packet has the address of where it's going, where it came from, and a piece of the actual data. They all travel separately and get put back together at the end.


## What Was Hard/ What I Fixed
One of the hardest part was fixing all the indentation errors. Python is really strict about spaces. I spent like an hour figuring out why my code wouldn't run, turns out i just needed to add 4 spaces before one line. Now i understand why clean code matters in security tools.


## How Security Teams Use This
Security teams (such as SOC analysts, network admins, etc.) use tools like this to monitor their networks for suspicious activity. They can spot if someone is trying to break in, or if a computer is sending data to werid places. The PCAP files are importantbecause you can save evidence and investigate it later.


## Requirements
- Python 3
- Scapy library
- Colorama library
- Linux with sudo access (for capturing packets)


## Installation
sudo apt install libpcap-dev -y
pip3 install scapy colorama --break-system packages


## Usage
sudo python3 favour_sniffer_v2.py


## Features
Protocol identification by port:
- Port 22: SSH
- Port 53: DNS
- Port 80: HTTPS
- And more...

Payload analysis shows:
- Hexadecimal view of raw data
- ASCII readable characters


## Sample Output
Time:                   2026-04-09 13:45:22
Source IP:              192.168.x.x
Destination IP:         142.168.x.x
Protocol:               TCP
Source Port:            54321 (Port-54321)
Dest Port:              443 (HTTPS)
Payload (first 50 bytes):
  HEX: 16030100c7010000c3...
  ASCII: ..GET / HTTP/ 1.1...


## Real Capture Analysis Example
Below is an actual output from monitoring a web browsing session:

- Time: 2026-04-09 13:45:23
- Source IP: 192.168.1.100 (example Internal workstation)
- Destination IP: 142.250.80.46 (Google server- verified via DNS)
- Protocol: TCP
- Dest Port: 443 (HTTPS - encrypted web traffic)
- Payload: TLS handshake (encrypted, cannot read content)

Security Assessment: LEGITIMATE
- Well-known destination (Google)
- Proper encryption (portt 443)
- Standard TLS handshake pattern


## Screenshot
## Wireshark Capture Analysis
![Wireshark Capture](wireshark_capture.png)
*PCAP file opened in Wireshark showing captured packets*


## Files in This Project
Files:
- favour_sniffer_v2.py - the main Python program i wrote
- favour_capture.pcap - a sample capture file you can open in Wireshark
- favour_capture_log.txt - saved packet log for analysis
- wireshark_analysis.png - screenshot of packets in Wireshark
- README.md - this file explains everything about the sniffer


## Knowledge Demonstrated
- Understanding of how packets travel across a network
- Difference betwwen TCP and UDP protocol
- How port numbers map to real service (HTTP=80, HTTPS=443
- How SOC analysts monitor network traffic for threats
- Python programming with Scapy and Colorama libraries
- Reading and interpreting packet payloads (HEX and ASCII)
- Industry standard PCAP file format used by Wireshark
- Importance of logging and timestamps in security work

## Author

Favour Ugochi Ogbonnaya
Cybersecurity Intern | CodeAlpha 
Task 1: Network Sniffer Implementation
April 2026

Contact: 
LinkedIn: www.linkedin.com/in/favour-ogbonnaya-0043422b5 


## !!Disclaimer
This tool is for educational purposes only.
Only use on networks you own or have permission to monitor.
