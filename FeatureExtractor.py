# MODULES 
import os
import numpy as np
import netStat as ns
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# Processes the traffic and computes the features one packet at a time
class FE:
    def __init__(self, file_path, limit=np.inf):
        self.path = file_path
        self.packets_limit = limit
        self.current_pkt_index = 0
        self.packets = None
        self.load_traffic()
        # AfterImage settings
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    # Loads the packets from a .pcap or .pcapng file  
    def load_traffic(self):
        # Loads the file
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"\033[91mFile [{self.path}] not found 🔥\033[0m")
        
        # Loads the packets
        if self.path.endswith(('.pcap', '.pcapng')):
            print("\033[90mLoading the traffic...\033[0m")
            self.packets = rdpcap(self.path)
            self.packets_limit = min(self.packets_limit, len(self.packets))
            print(f"\033[92mSuccess!\n\033[90mLoaded [{len(self.packets)}] packets\033[0m")
        else:
            raise ValueError(f"\033[91mFile: {self.path} is not a pcap or pcapng file 🔥\033[0m")

    def compute_features(self):
        # Checks if the packet index is out of bounds
        if self.current_pkt_index >= self.packets_limit:
            return []

        packet = self.packets[self.current_pkt_index]
        timestamp = packet.time
        framelen = len(packet)
        
        # IPv4
        if packet.haslayer(IP): 
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
        # IPv6
        elif packet.haslayer(IPv6):
            srcIP = packet[IPv6].src
            dstIP = packet[IPv6].dst
        # IP layer unknown
        else:
            srcIP = ''
            dstIP = ''

        # TCP
        if packet.haslayer(TCP):
            srcproto = str(packet[TCP].sport)
            dstproto = str(packet[TCP].dport)
        # UDP
        elif packet.haslayer(UDP):
            srcproto = str(packet[UDP].sport)
            dstproto = str(packet[UDP].dport)
        # Transport layer unknown
        else:
            srcproto = ''
            dstproto = ''

        # MAC addresses
        srcMAC = packet.src
        dstMAC = packet.dst
        # ARP
        if srcproto == '':
            if packet.haslayer(ARP):
                srcproto = 'arp'
                dstproto = 'arp'
                srcIP = packet[ARP].psrc
                dstIP = packet[ARP].pdst
            # ICMP
            elif packet.haslayer(ICMP):
                srcproto = 'icmp'
                dstproto = 'icmp'
            # Other protocol
            elif srcIP + srcproto + dstIP + dstproto == '':
                srcIP = packet.src
                dstIP = packet.dst

        # Increments the packet index
        self.current_pkt_index += 1

        try:
            # Computes the features
            return self.nstat.updateGetStats(srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp))
        except Exception as e:
            # Prints the occurred error
            print(f"\033[91m{e}\033[0m")  
            return []

    # Returns the number of features present in the feature vector
    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
