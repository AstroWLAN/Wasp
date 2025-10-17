# IMPORTS 
import os
import hashlib
import numpy as np
import Kitsune.netStat as ns
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.l2 import CookedLinux as SLL
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
            print("\033[92mDone\033[0m")
            print(f"\033[90m{len(self.packets)} packets loaded\033[0m")
        else:
            raise ValueError(f"\033[91mFile {self.path} is not a pcap or pcapng file 🔥\033[0m")

    # Computes the feature vector for the current packet
    def compute_features(self):
        # Checks if the packet index is out of bounds
        if self.current_pkt_index >= self.packets_limit:
            return [], None

        packet = self.packets[self.current_pkt_index]
        timestamp = packet.time
        framelen = len(packet)

        # SLL v1 [ Linux cooked capture ]
        if packet.haslayer(SLL):
            # Default values -> empty fields
            srcIP = dstIP = ''
            srcproto = dstproto = ''
            srcMAC = dstMAC = ''
            # Extract IP addresses [ IPv4 • IPv6 ] or ARP endpoints
            if packet.haslayer(IP):
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
            elif packet.haslayer(IPv6):
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
            elif packet.haslayer(ARP):
                srcIP = packet[ARP].psrc
                dstIP = packet[ARP].pdst
                srcproto = 'arp'
                dstproto = 'arp'

            # Transport-layer ports • ICMP
            if srcproto == '' and dstproto == '':
                if packet.haslayer(TCP):
                    srcproto = str(packet[TCP].sport)
                    dstproto = str(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    srcproto = str(packet[UDP].sport)
                    dstproto = str(packet[UDP].dport)
                elif packet.haslayer(ICMP):
                    srcproto = 'icmp'
                    dstproto = 'icmp'

            # MAC addresses handling
            # IF both IPs are known then synthesize both MACs from the IPs
            # ... otherwise use sll.addr for the "known direction" based on pkttype and synthesize the missing MAC from the available info
            sll = packet[SLL]
            sll_addr = getattr(sll, 'addr', b'') or b''
            sll_pkttype = getattr(sll, 'pkttype', 0)

            if srcIP and dstIP:
                # Synthesize MACs from IPs 
                smac_b, dmac_b = ethernet_formatter(srcIP, dstIP)
                srcMAC = self._to_str_mac(smac_b)
                dstMAC = self._to_str_mac(dmac_b)
            else:
                # Use single SLL address 
                sll_mac_str = self._to_str_mac(sll_addr) if isinstance(sll_addr, (bytes, bytearray)) else str(sll_addr or '')
                if sll_mac_str:
                    if sll_pkttype == 4:
                        srcMAC = sll_mac_str
                        peer_tag = f"{dstIP or 'dst'}|{srcIP or 'src'}|{sll_pkttype}|peer"
                        dstMAC = self._to_str_mac(self._synth_mac(peer_tag))
                    else:
                        dstMAC = sll_mac_str
                        peer_tag = f"{srcIP or 'src'}|{dstIP or 'dst'}|{sll_pkttype}|peer"
                        srcMAC = self._to_str_mac(self._synth_mac(peer_tag))
                else:
                    # IF there is no SLL addr synthesize both [ fallback ]
                    src_tag = f"{srcIP or 'src'}|{dstIP or 'dst'}|{sll_pkttype}|A"
                    dst_tag = f"{srcIP or 'src'}|{dstIP or 'dst'}|{sll_pkttype}|B"
                    srcMAC = self._to_str_mac(self._synth_mac(src_tag))
                    dstMAC = self._to_str_mac(self._synth_mac(dst_tag))

            # Computes the flow ID
            flowID = self.compute_flowID(srcIP, dstIP, srcproto, dstproto)

            # Increments the packet index
            self.current_pkt_index += 1

            try:
                # Computes the features
                return self.nstat.updateGetStats(srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp)), flowID
            except Exception as e:
                # Prints the occurred error
                print(f"\033[91m{e}\033[0m")  
                return [], None

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
            # Other protocols
            elif srcIP + srcproto + dstIP + dstproto == '':
                srcIP = packet.src
                dstIP = packet.dst

        # Computes the flow ID
        flowID = self.compute_flowID(srcIP, dstIP, srcproto, dstproto)

        # Increments the packet index
        self.current_pkt_index += 1

        try:
            # Computes the features
            return self.nstat.updateGetStats(srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp)), flowID
        except Exception as e:
            # Prints the occurred error
            print(f"\033[91m{e}\033[0m")  
            return [], None

    # Returns the number of features present in the feature vector
    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
    
    # Computes the flow ID for the current packet
    def compute_flowID(self, srcIP, dstIP, srcproto, dstproto):
        return f"{srcIP}:{srcproto}_{dstIP}:{dstproto}"

    # SLL Helpers
    # Generate a synthetic MAC address 
    def _synth_mac(self, tag: str) -> bytes:
        # Deterministic, locally-administered and unicast MAC from an arbitrary tag
        h = hashlib.sha256(tag.encode('utf-8')).digest()
        mac = bytearray(h[:6])
        # Set local bit [ clear multicast bit ]
        mac[0] = (mac[0] | 0x02) & 0xFE  
        return bytes(mac)

    def _to_str_mac(self, x) -> str:
        # Convert the bytes to a readable MAC string
        if isinstance(x, (bytes, bytearray)):
            return ':'.join(f'{b:02x}' for b in x)
        s = str(x or '')
        # Normalize the string if it doesn't contain ':'
        if s and ':' not in s and len(s) in (12, 16):  
            try:
                bs = bytes.fromhex(s[:12])
                return ':'.join(f'{b:02x}' for b in bs)
            except Exception:
                pass
        return s

# Both IPs known
# Generate a synthetic pair of MAC addresses starting from the source and destination IP addresses of a packet
def ethernet_formatter(source_ip, destination_ip):
    # Input validation
    if not isinstance(source_ip, str) or not source_ip:
        raise ValueError("\033[1;91mError 🔥\n\033[0;90mSource IP address must be a non-empty string\n\033[0m")
    if not isinstance(destination_ip, str) or not destination_ip:
        raise ValueError("\033[1;91mError 🔥\n\033[0;90mDestination IP address must be a non-empty string\n\033[0m")
    # Synthesize a MAC address from an IP address using SHA-256 hashing
    # Collisions are possibile but EXTREMELY rare 
    def mac_forger(ip):
        try:
            # Create the SHA-256 hash of the IP address
            ip_bytes = ip.encode('utf-8')
            hash_bytes = hashlib.sha256(ip_bytes).digest()
            # Take the first 6 bytes for the MAC address [ 48 bits ]
            mac_bytes = bytearray(hash_bytes[:6])
            # Avoid multicast and official OUI addresses -> highlight the synthetic nature of the MAC address
            mac_bytes[0] = (mac_bytes[0] | 0x02) & 0xFE
            # Return the address as bytes 
            return bytes(mac_bytes)
        # Exception handling : log the error in the console
        except Exception as e:
            raise ValueError(f"\033[1;91mError 🔥\n\033[0;90mFailed to synthesize the MAC address for {ip}: {e}\n\033[0m")
    try:
        # Synthesize the MAC addresses for both source and destination IPs
        source_mac = mac_forger(source_ip)
        dest_mac = mac_forger(destination_ip)
        return source_mac, dest_mac
    # Exception handling : log the error in the console
    except Exception as e:
        raise ValueError(f"\033[1;91mError 🔥\n\033[0;90mFailed to synthesize the MAC addresses: {e}\n\033[0m")