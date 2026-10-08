from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import IP

#files loaded
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

def Show_Packet_info(pkt, proto):
        print("SOURCE IP: ", pkt[IP].src,"DESTINATION IP: ", pkt[IP].dst ,"PROTOCOL: ", proto ,"SOURCE port: ", pkt.sport ,"DESTINATION port: ", pkt.dport)


## lists
TCPlist = []
UDPlist = []

## loop first 20
for pkt in packets[:20]:
    if TCP in pkt:
        TCPlist.append(pkt)
        protocol = "TCP"
        Show_Packet_info(pkt, protocol)
    if UDP in pkt:
        UDPlist.append(pkt)
        protocol = "UDP"
        Show_Packet_info(pkt, protocol)
    else:
        continue
        #protocol = "neither TCP nor UDP"
        #Show_Packet_info(pkt, protocol)
  

######
# rest of packets
## loop
for pkt in packets[21:]:
    if TCP in pkt:
        TCPlist.append(pkt)
    if UDP in pkt:
        UDPlist.append(pkt)

print("Total number of TCP packets", len(TCPlist))
print("Total number of UDP packets", len(UDPlist))

