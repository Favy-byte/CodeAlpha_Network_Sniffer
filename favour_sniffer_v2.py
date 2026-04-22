from scapy.all import sniff, IP, TCP, UDP, wrpcap
from colorama import Fore, Style
from datetime import datetime

# Track statistics
stats = {"TCP": 0, "UDP": 0, "Other": 0}

# Suspicious ports to watch
SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 1337, 8080, 6667]

# Store packet for later saving
captured_packets = []

def get_service_name(port):
  # Convert port number to service name
  services ={ 
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 8080: "HTTP_Alt", 6667: "IRC"
  }
  return services.get(port, f"Port-{port}")

def save_to_log(src, dst, protocol, port):
  # Save packet info to log file
  timestamp = datetime.now().strftime('%y-%m-%d %H:%M:%S')
  with open("favour_capture_log.txt", "a") as f:
    f.write(f"[{timestamp}] {src} --> {dst} | {protocol} | Port: {port}\n")

def analyze_packet(packet):
  captured_packets.append(packet)
  global stats
  timestamp = datetime.now().strftime('%y-%m-%d %H:%M:%S')

  print (f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
  print (f"{Fore.WHITE}Time:{Style.RESET_ALL}              {timestamp}")

  # Check if packet has IP layer
  if packet.haslayer(IP):
    ip = packet[IP]

    print (f"{Fore.GREEN}Source IP:{Style.RESET_ALL}        {ip.src}")
    print (f"{Fore.RED}Destination IP: {Style.RESET_ALL}    {ip.dst}")

    # TCP packets (websites, email, etc.)
    if packet.haslayer(TCP):
      tcp = packet[TCP]
      stats["TCP"] += 1

      src_service = get_service_name(tcp.sport)
      dst_service = get_service_name(tcp.dport)

      print (f"{Fore.YELLOW}Protocol: {Style.RESET_ALL}       TCP")
      print (f"{Fore.YELLOW}Source Port: {Style.RESET_ALL}  {tcp.sport} ({src_service})")
      print (f"{Fore.YELLOW}Dest Port: {Style.RESET_ALL}   {tcp.dport} ({dst_service})")

      # PayLoad
      if tcp.payload:
        payload = bytes(tcp.payload)
        print (f"{Fore.WHITE}PayLoad:{Style.RESET_ALL}    {payload[:50]}...")

      # Better alerts
      if tcp.dport in SUSPICIOUS_PORTS:
        print (f"{Fore.RED}[!] ALERT:{Style.RESET_ALL}    Suspicious port {tcp.dport} detected!")

      # Log it
      save_to_log(ip.src, ip.dst, "TCP", tcp.dport)
 
      # Flag suspicious ports
      if tcp.dport in [22, 23, 3389, 4444, 1337, 8080, 6667]:
        print (f"{Fore.RED}[!] ALERT:{Style.REST_ALL}        Remote access detected!")

    # UDP packets (DNS, video calls, etc. )
    elif packet.haslayer(UDP):
      udp = packet[UDP]
      stats["UDP"] += 1

      src_service = get_service_name(udp.sport)
      dst_service = get_service_name(udp.dport)

      print (f"{Fore.YELLOW}Protocol: {Style.RESET_ALL}            UDP")
      print (f"{Fore.YELLOW}Source Port:{Style.RESET_ALL}        {udp.sport}  ({src_service})")
      print (f"{Fore.YELLOW}Dest Port: {Style.RESET_ALL}         {udp.dport}  ({dst_service})")


    # Other IP protocols
    else:
      stats["Other"] += 1
      print (f"{Fore.YELLOW}Protocol: {Style.RESET_ALL}           Other (IP protocol {ip.protocol})")

  # Non-IP packets (ARP, etc. )
  else:
    print (f"{Fore.MAGENTA}Non-IP Packet:{Style.RESET_ALL}  {packet.summary()}")

  print (f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def print_stats():
  # Display capture statistics
  print (f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
  print (f"{Fore.WHITE}CAPTURE STATISTICS:{Style.RESET_ALL}")
  print (f"  TCP packets:  {stats['TCP']}")
  print (f"  UDP packets:  {stats['UDP']}")
  print (f"  Other packets: {stats['Other']}")
  print (f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

# Main program
print (f"{Fore.CYAN}Favour's Network Sniffer{Style.RESET_ALL}")
print (f"{Fore.WHITE}Capturing 20 packets...{Style.RESET_ALL}")
print ("Press Ctrl+C to stop early\n")

try:
  sniff(count=20, prn=analyze_packet, store=False)
except KeyboardInterrupt:
  print (f"\n{Fore.YELLOW}Stopped by user{Style.RESET_ALL}")

def save_to_pcap():
  # Save captured packets to PCAP file
  if captured_packets:
    filename = "favour_capture.pcap"
    wrpcap(filename, captured_packets)
    print (f"\n{Fore.GREEN}[+] Saved {len(captured_packets)} packets to {filename}{Style.RESET_ALL}")
    print (f"{Fore.YELLOW}[*] Open in Wireshark: wireshark {filename}{Style.RESET_ALL}")
  else:
    print (f"\n{Fore.RED}[!] No packets to save{Style.RESET_ALL}")

print_stats()
save_to_pcap()
print (f"{Fore.GREEN}Capture complete! Log saved to favour_capture_log.txt{Style.RESET_ALL}")


