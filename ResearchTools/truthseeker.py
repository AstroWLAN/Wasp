import os
import sys
import pandas as pd
import numpy as np
from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn
import argparse

# Customizes the appearance of TimeElapsedColumn in rich.progress
class WhiteTimeElapsedColumn(TimeElapsedColumn):
    def render(self, task):
        elapsed_text = super().render(task)
        elapsed_text.style = "white"
        return elapsed_text

custom_columns = [
    # Configures the progress bars
    TextColumn("[white]{task.description}"),
    WhiteTimeElapsedColumn(),
    BarColumn(),
    TextColumn("[white]{task.percentage:>3.0f}%"),
]

def load_flow_labels(csv_path):
    """Loads flowID and label pairs from CSV file"""
    try:
        print("\033[90mLoading flow labels...\033[0m")
        
        # Load the CSV file
        df = pd.read_csv(csv_path)
        
        # Check if required columns exist
        if 'flowID' not in df.columns or 'label' not in df.columns:
            raise Exception("CSV file must contain 'flowID' and 'label' columns")
        
        # Create a dictionary for fast lookup
        flow_labels = {}
        for _, row in df.iterrows():
            flow_labels[row['flowID']] = row['label']
        
        print(f"\033[90mLoaded {len(flow_labels)} flow-label pairs\033[0m")
        print("\033[92mDone\033[0m")
        
        return flow_labels
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")
        return None

def compute_flowID(src_ip, src_port, dst_ip, dst_port, proto):
    """Computes flowID using the specified format"""
    return f"{src_ip}_{src_port}_{dst_ip}_{dst_port}_{proto.lower()}"

def extract_packet_info(packet):
    """Extracts packet information similar to FeatureExtractor.py"""
    try:
        timestamp = packet.time
        framelen = len(packet)
        
        # MAC addresses
        srcMAC = str(packet.src) if hasattr(packet, 'src') else ''
        dstMAC = str(packet.dst) if hasattr(packet, 'dst') else ''
        
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
            proto = 'tcp'
        # UDP
        elif packet.haslayer(UDP):
            srcproto = str(packet[UDP].sport)
            dstproto = str(packet[UDP].dport)
            proto = 'udp'
        # Transport layer unknown
        else:
            srcproto = ''
            dstproto = ''
            proto = ''

        # ARP
        if srcproto == '':
            if packet.haslayer(ARP):
                srcproto = 'arp'
                dstproto = 'arp'
                proto = 'arp'
                srcIP = packet[ARP].psrc
                dstIP = packet[ARP].pdst
            # ICMP
            elif packet.haslayer(ICMP):
                srcproto = 'icmp'
                dstproto = 'icmp'
                proto = 'icmp'
            # Other protocols
            elif srcIP + srcproto + dstIP + dstproto == '':
                # For packets without IP layer, try to get MAC addresses as fallback
                try:
                    srcIP = str(packet.src) if hasattr(packet, 'src') else ''
                    dstIP = str(packet.dst) if hasattr(packet, 'dst') else ''
                except:
                    srcIP = ''
                    dstIP = ''
                proto = 'other'

        return {
            'timestamp': timestamp,
            'framelen': framelen,
            'srcMAC': srcMAC,
            'dstMAC': dstMAC,
            'srcIP': srcIP,
            'dstIP': dstIP,
            'srcproto': srcproto,
            'dstproto': dstproto,
            'proto': proto
        }
    except Exception as e:
        # Return default values if packet parsing fails
        return {
            'timestamp': 0,
            'framelen': 0,
            'srcMAC': '',
            'dstMAC': '',
            'srcIP': '',
            'dstIP': '',
            'srcproto': '',
            'dstproto': '',
            'proto': 'unknown'
        }

def process_pcap_file(flow_labels, pcap_path, output_name, destination_folder=None):
    """Processes PCAP file and labels packets based on flowID"""
    try:
        # Check if file exists
        if not os.path.isfile(pcap_path):
            print(f"\033[91mFile [{pcap_path}] not found 🔥\033[0m")
            return
        
        # Check if it's a PCAP file
        if not pcap_path.endswith(('.pcap', '.pcapng')):
            print(f"\033[91mFile {pcap_path} is not a pcap or pcapng file 🔥\033[0m")
            return
        
        print("\033[90mLoading PCAP file...\033[0m")
        packets = rdpcap(pcap_path)
        print(f"\033[90mLoaded {len(packets)} packets\033[0m")
        
        # Determine output folder
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.csv")
        else:
            output_file = f"{output_name}.csv"
        
        print("\033[90mProcessing packets...\033[0m")
        
        # Initialize counters
        unknown_packets = 0
        labeled_packets = 0
        
        # Prepare data for CSV
        csv_data = []
        
        # Process packets with progress bar
        with Progress(*custom_columns) as progress:
            task = progress.add_task("Processing packets", total=len(packets))
            
            for i, packet in enumerate(packets):
                try:
                    # Extract packet information
                    packet_info = extract_packet_info(packet)
                    
                    # Compute flowID
                    flowID = compute_flowID(
                        packet_info['srcIP'], 
                        packet_info['srcproto'], 
                        packet_info['dstIP'], 
                        packet_info['dstproto'], 
                        packet_info['proto']
                    )
                    
                    # Check if flowID exists in our labels
                    if flowID in flow_labels:
                        label = flow_labels[flowID]
                        labeled_packets += 1
                    else:
                        label = 0  # Unknown packet
                        unknown_packets += 1
                    
                    # Add to CSV data
                    row = {
                        'flowID': flowID,
                        'label': label,
                        'timestamp': packet_info['timestamp'],
                        'framelen': packet_info['framelen'],
                        'srcMAC': packet_info['srcMAC'],
                        'dstMAC': packet_info['dstMAC'],
                        'srcIP': packet_info['srcIP'],
                        'dstIP': packet_info['dstIP'],
                        'srcproto': packet_info['srcproto'],
                        'dstproto': packet_info['dstproto'],
                        'proto': packet_info['proto']
                    }
                    csv_data.append(row)
                    
                except Exception as e:
                    # Skip problematic packets and continue
                    print(f"\033[93mWarning: Skipping packet {i+1} due to error: {str(e)}\033[0m")
                    continue
                
                # Update progress
                progress.update(task, completed=i + 1)
        
        # Save to CSV
        print("\033[90mSaving results...\033[0m")
        df = pd.DataFrame(csv_data)
        df.to_csv(output_file, index=False)
        
        print(f"\033[1;92mDone\033[0m")
        print(f"\033[90mResults saved as {output_file}\033[0m")
        print(f"\033[90mTotal packets processed: {len(packets)}\033[0m")
        print(f"\033[90mLabeled packets: {labeled_packets}\033[0m")
        print(f"\033[90mUnknown packets: {unknown_packets}\033[0m")
        
        return unknown_packets
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")
        return None

def flow_labeler(destination_folder=None):
    """Main function for flow labeling"""
    print("\033[1;37m\nFlow Labeler 🏷️\033[0m\033[90m\nLabel packets based on flowID-label pairs\n\033[0m")
    
    # Get all inputs upfront
    csv_path = input("\033[37mFlow labels CSV file [ \033[90mpath\033[37m ] : \033[0m")
    pcap_path = input("\033[37mPCAP file [ \033[90mpath\033[37m ] : \033[0m")
    output_name = input("\033[37mOutput file name [ \033[90mwithout .csv\033[37m ] : \033[0m")
    
    print("\033[90m\nStarting computation...\033[0m")
    
    # Load flow labels
    flow_labels = load_flow_labels(csv_path)
    if flow_labels is None:
        return
    
    # Process PCAP file
    unknown_count = process_pcap_file(flow_labels, pcap_path, output_name, destination_folder)
    
    if unknown_count is not None:
        print(f"\033[90m\nUnknown packets count: {unknown_count}\033[0m")

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label packets in PCAP file based on flowID-label pairs from CSV")
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the output file')
    args = parser.parse_args()
    
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mFlow Labeler\n\033[0m")
    flow_labeler(destination_folder=args.destination) 