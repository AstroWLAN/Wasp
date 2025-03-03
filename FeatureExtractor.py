# MODULES
import os
import netStat as ns
import numpy as np
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, TCP, UDP, ICMP

#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# Uses scapy to parse pcap files and extract network features
class FE:
    def __init__(self, file_path, limit=np.inf):
        self.path = file_path
        self.limit = limit
        self.curPacketIndx = 0
        self.scapyin = None
        self.__prep__()
        
        # Initialize feature extractor
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def __prep__(self):
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"File: {self.path} does not exist")
        
        if not self.path.endswith('.pcap'):
            raise ValueError(f"File: {self.path} is not a valid pcap file")
            
        print("Reading PCAP file via Scapy...")
        self.scapyin = rdpcap(self.path)
        self.limit = min(len(self.scapyin), self.limit)
        print(f"Loaded {len(self.scapyin)} Packets.")

    def get_next_vector(self):
        if self.curPacketIndx == self.limit:
            return []

        packet = self.scapyin[self.curPacketIndx]
        IPtype = np.nan
        timestamp = packet.time
        framelen = len(packet)
        
        # Extract IP information
        if packet.haslayer(IP):  # IPv4
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
            IPtype = 0
        elif packet.haslayer(IPv6):  # IPv6
            srcIP = packet[IPv6].src
            dstIP = packet[IPv6].dst
            IPtype = 1
        else:
            srcIP = ''
            dstIP = ''

        # Extract protocol information
        if packet.haslayer(TCP):
            srcproto = str(packet[TCP].sport)
            dstproto = str(packet[TCP].dport)
        elif packet.haslayer(UDP):
            srcproto = str(packet[UDP].sport)
            dstproto = str(packet[UDP].dport)
        else:
            srcproto = ''
            dstproto = ''

        srcMAC = packet.src
        dstMAC = packet.dst

        # Handle special protocols
        if srcproto == '':  # L2/L1 level protocol
            if packet.haslayer(ARP):  # ARP
                srcproto = 'arp'
                dstproto = 'arp'
                srcIP = packet[ARP].psrc
                dstIP = packet[ARP].pdst
                IPtype = 0
            elif packet.haslayer(ICMP):  # ICMP
                srcproto = 'icmp'
                dstproto = 'icmp'
                IPtype = 0
            elif srcIP + srcproto + dstIP + dstproto == '':  # other protocol
                srcIP = packet.src
                dstIP = packet.dst

        self.curPacketIndx += 1

        try:
            return self.nstat.updateGetStats(
                IPtype, srcMAC, dstMAC, srcIP, srcproto, 
                dstIP, dstproto, int(framelen), float(timestamp)
            )
        except Exception as e:
            print(f"Error processing packet: {e}")
            return []

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
