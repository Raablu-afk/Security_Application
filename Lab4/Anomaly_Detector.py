from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import IP

#files loaded
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

TCPlist = []
UDPlist = []

IPmasterList = {}
alerted = set()

# Obtain each packet's source IP using pkt[IP].src.

for pkt in packets:

    #count
    if TCP in pkt:
        TCPlist.append(pkt)
    elif UDP in pkt:
        UDPlist.append(pkt)
    else:
        continue

    #verification
    if IP not in pkt:
        continue

    src = pkt[IP].src
    now = float(pkt.time)

    if src not in IPmasterList:
        IPmasterList[src] = [now]
    else:
        recent = []
        for t in IPmasterList[src]:
            if now - t <= 5:
                recent.append(t)
        IPmasterList[src] = recent
        IPmasterList[src].append(now)

    #alert
    if len(IPmasterList[src]) > 20 and src not in alerted:
        print("ALERT:", src, "sent more than 20 packets within 5 seconds")
        alerted.add(src)

  
#print
print("Number of suspicious adresses: ", len(alerted))
print("Total number of TCP packets", len(TCPlist))
print("Total number of UDP packets", len(UDPlist))