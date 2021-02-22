#!/usr/bin/env python3
import argparse
from scapy.all import *
from firewall import *
import time
from datetime import datetime




def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='iface')
    parser.add_argument('--ourIP', dest='ourIP')
    args = parser.parse_args()
    return args

def sniffer(iface):
    sniff(iface=iface, prn=analyze_packet, count=0)

def analyze_packet(pkt):
    myPacket = {}
    logTime = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    myPacket["timeStamp"] = logTime
    myPacket["srcIP"] = pkt[IP].src
    myPacket["srcPort"] = pkt[TCP].sport
    myPacket["dstIP"] = pkt[IP].dst
    myPacket["dstPort"] = pkt[TCP].dport
    myPacket["rawPayload"] = str(pkt[TCP].payload)
    #detect our attacks to bypass it
    if  (  myPacket["srcPort"] in servicePorts ):
        pass
    else:
        if TCP in pkt:
            body = str(pkt[TCP].payload)
            
            for i in malicious:
                if i in body:
                    # ip = IP(src=pkt[IP].dst,dst=pkt[IP].src, flags='DF', id=0) 
                    # tcp = TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags='R',seq=pkt.ack, window=0)
                    # msg = ip/tcp
                    # msg.show()
                    # send(msg)  
                    print(str([pkt[TCP].sport]))
                    add_rule(str(pkt[TCP].sport))
                    time.sleep(10)
                    flush()


if __name__ == "__main__":

    args = get_arguments()
    if args.iface == None or args.ourIP == None:
         print("You have to add an interface like : ./script --interface <interface> --ourIP <IP>")
    else:
        with open('payloads.txt') as f:
            malicious = f.read().splitlines()
        ourIP = args.ourIP
        servicePorts = [ '10001', '10002', '10003', '10004']    
        sniffer(args.iface)

