from scapy.all import sniff

def show_packet(packet):
print (packet.summary())

print ("Starting packet capture...")
print ("Catching 5 packets...")
print ("-" * 50)

sniff(count=5, prn=show_packet)

print ("-" * 50)
print ("Done!")
