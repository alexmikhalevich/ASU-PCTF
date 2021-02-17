#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime
import os
import sys


import logging
import time
from logging.handlers import RotatingFileHandler
#----------------------------------------------------------------------
def create_rotating_log(path, log):
    """
    Creates a rotating log
    maxBytes = 880    #5M 5242880
    backupCount = 100 ## max number of log files to keep before rotate
    """
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)
    
    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=5242880,
                                  backupCount=100)
    logger.addHandler(handler)
    logger.info(log)
         
#----------------------------------------------------------------------

    
   
def call_back(packet, logFilePath):
    #print(packet.summary())
    #print(type(packet[TCP].payload))
    myPacket = {}
    logTime = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    myPacket["timeStamp"] = logTime
    myPacket["srcIP"] = packet[IP].src
    myPacket["srcPort"] = packet[TCP].sport
    myPacket["dstIP"] = packet[IP].dst
    myPacket["dstPort"] = packet[TCP].dport
    myPacket["rawPayload"] = str(packet[TCP].payload)
    if str(type(packet[TCP].payload)) == "<class 'scapy.packet.Raw'>":
        print(myPacket)
        create_rotating_log(logFilePath, myPacket)
        

def startServiceAudit(port, logFilePath, nic):
    
    myFilter = 'dst port ' + str(port)
    sniff(iface = nic, filter = myFilter ,prn =lambda r:call_back(r, logFilePath), store = 0, count = 0)


if __name__ == "__main__":

    if len(sys.argv) != 2:
         print("You have to add port like : ./script <port>")
    else:
        port = str(sys.argv[1])
        logFilePath = "./logs/packets_" + port + ".log"
        nic = "ens33"
        startServiceAudit(port, logFilePath, nic)
