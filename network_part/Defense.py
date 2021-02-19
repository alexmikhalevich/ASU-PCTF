#!/usr/bin/env python3
import argparse
from scapy.all import *
from firewall import *
import time

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='iface')
    args = parser.parse_args()
    return args

def sniffer(iface):
    sniff(iface=iface, prn=analyze_packet, count=0)

def analyze_packet(pkt):
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
    if args.iface == None:
         print("You have to add an interface like : ./script --interface <interface>")
    else:
        with open('payloads.txt') as f:
            malicious = f.read().splitlines()
            
        sniffer(args.iface)

