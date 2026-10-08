from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP

#files loaded
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

## lists
TCPlist = []
TCP80list = []
UDP53list = []

## loop
for pkt in packets:
    if TCP in pkt:
        TCPlist.append(pkt)
        if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
            TCP80list.append(pkt)
    if UDP in pkt:
        if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            UDP53list.append(pkt)

## print
print("the number of TCP packets is: ", len(TCPlist))
print("the number of TCP 80 packets is: ", len(TCP80list))
print("the number of UDP 53 packets is: ", len(UDP53list))