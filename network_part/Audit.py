#!/usr/bin/env python3
from scapy.all import *

nic = "ens33"
myFilter = 'dst port 5555'
def call_back(packet):
    #print(packet.summary())
    #print(type(packet[TCP].payload))
    myPacket = {}
    myPacket["srcIP"] = packet[IP].src
    myPacket["srcPort"] = packet[TCP].sport
    myPacket["dstIP"] = packet[IP].dst
    myPacket["dstPort"] = packet[TCP].dport
    myPacket["rawPayload"] = str(packet[TCP].payload)
    if str(type(packet[TCP].payload)) == "<class 'scapy.packet.Raw'>":
        print(myPacket)
    
      
    

sniff(iface=nic, filter= myFilter,prn=call_back, store=0, count=0) 