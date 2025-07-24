# truthseeker.py 
# Generate a ground truth .csv file combining the information from a .pcap file and a .csv file containing the labels for the flows
# Target : TON-IoT dataset from https://research.unsw.edu.au/projects/toniot-datasets
# Author : Dario Crippa [ AstroWLAN ]

# IMPORTS
import os
import pandas as pd
import argparse
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

# Write batch of packets to CSV file
def write_batch(batch_packets, output_file):
    df = pd.DataFrame(batch_packets)
    df.to_csv(output_file, mode='a', header=False, index=False)

# Load the flow labels from the .csv file
def load_flow_labels(csv_path):
    try:
        print("\033[1;37mFlow Labels 🏷️\033[0m")
        print("\033[0;90mLoading flow labels with pandas...\033[0m")
        # Use pandas to read the .csv file
        dataframe = pd.read_csv(csv_path)
        # Required columns existence
        if 'flowID' not in dataframe.columns or 'label' not in dataframe.columns:
            raise Exception("The .csv file must contain the 'flowID' and 'label' columns")
        # Generate a dictionary for a faster lookup
        labels = dict(zip(dataframe['flowID'], dataframe['label']))
        print(f"\033[90mLoaded {len(labels)} flowID-label pairs\033[0m")
        print("\033[1;92mDone\033[0m")
        return labels
     # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        return None

# Compute the flowID concatenating packet parsed information
def compute_flowID(src_ip, src_port, dst_ip, dst_port, proto):
    return f"{str(src_ip)}_{str(src_port)}_{str(dst_ip)}_{str(dst_port)}_{str(proto).lower()}"

# Parse the packet in order to retrieve useful information
def parse_packet(packet):
    src_ip = dst_ip = src_port = dst_port = '-'
    proto = 'other'
    timestamp = packet.time
    
    # IPv4
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            proto = 'tcp'
        elif packet.haslayer(UDP):
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            proto = 'udp'
        elif packet.haslayer(ICMP):
            src_port = str(packet[ICMP].type)  # ICMP type
            dst_port = str(packet[ICMP].code)  # ICMP code
            proto = 'icmp'
        else:
            # Handle other protocols - collect basic info
            proto = ''
            src_port = dst_port = '-'
    # IPv6
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        if packet.haslayer(TCP):
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            proto = 'tcp'
        elif packet.haslayer(UDP):
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            proto = 'udp'
        elif packet.haslayer(ICMP):
            src_port = str(packet[ICMP].type)  
            dst_port = str(packet[ICMP].code)
            proto = 'icmp'
        else:
            # Handle other protocols - collect basic info
            proto = ''
            src_port = dst_port = '-'
    elif packet.haslayer(ARP):
        # ARP packets
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst 
        src_port = str(packet[ARP].op)  
        dst_port = '-'
        proto = 'arp'
    else:
        # Non-IP packets
        proto = 'other'

    # Return a Python dictionary with the parsed information
    return {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'proto': proto
    }

# Label the packets in the .pcap file based on the flow labels in the .csv file
def packet_labeler(flow_labels, pcap_path, output_name, destination_folder=None):
    try:
        # File existance
        if not os.path.isfile(pcap_path):
            print(f"\033[1;91mError 🔥\n\033[0;90mThe .pcap file at {pcap_path} does not exist\n\033[0m")
            return
        # Format check : is the file a .pcap or .pcapng file?
        if not pcap_path.endswith(('.pcap', '.pcapng')):
            print(f"\033[1;91mError 🔥\n\033[0;90mThe file {pcap_path} is not a .pcap or .pcapng file\n\033[0m")
            return

        # Processing the .pcap file with streaming approach
        print("\033[90mOpening the .pcap file...\033[0m")

        # Establish the output file path
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.csv")
        else:
            output_file = f"{output_name}.csv"
        # Create empty DataFrame with headers and write to CSV
        columns = ['flowID', 'label', 'ts', 'proto', 'src_ip', 'src_port', 'dst_ip', 'dst_port']
        pd.DataFrame(columns=columns).to_csv(output_file, index=False)
        
        print("\033[90mLabeling the packets...\033[0m", end="", flush=True)
        BATCH_SIZE = 10000
        batch_packets = []
        skipped = 0
        unknown = 0
        packet_count = 0
        
        with PcapReader(pcap_path) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                # Update pulsing indicator every 1000 packets
                if packet_count % 1000 == 0:
                    symbols = [" ", "*", " ", "*"]
                    symbol = symbols[(packet_count // 1000) % len(symbols)]
                    print(f"\r\033[90mLabeling the packets...{symbol}\033[0m", end="", flush=True)
                try:
                    packet_info = parse_packet(packet)
                    if packet_info is None:
                        skipped += 1
                        continue  
                    
                    if packet_info['proto'] == 'other':
                        flowID = 'unknown'
                    else:
                        flowID = compute_flowID(
                            packet_info['src_ip'],
                            packet_info['src_port'],
                            packet_info['dst_ip'],
                            packet_info['dst_port'],
                            packet_info['proto']
                        )
                    
                    # Only check flow labels for TCP/UDP/ICMP packets
                    if packet_info['proto'] in ['tcp', 'udp', 'icmp'] and flowID in flow_labels:
                        label = flow_labels[flowID]
                    else:
                        # Protocols that are not TCP, UDP or ICMP are labeled as benign since they are not relevant for the attack 
                        label = 0
                        if packet_info['proto'] in ['tcp', 'udp', 'icmp']:
                            unknown += 1
                    
                    row = {
                        'flowID': flowID,
                        'label': label,
                        'ts': packet_info['timestamp'],
                        'proto': packet_info['proto'],
                        'src_ip': packet_info['src_ip'],
                        'src_port': packet_info['src_port'],
                        'dst_ip': packet_info['dst_ip'],
                        'dst_port': packet_info['dst_port']
                    }
                    batch_packets.append(row)
                    
                    # Write batch when it reaches BATCH_SIZE
                    if len(batch_packets) >= BATCH_SIZE:
                        write_batch(batch_packets, output_file)
                        batch_packets = []

                except Exception as e:
                    print(f"\033[1;93mWarning ⚠️\n\033[0;90mSkipping packet {packet_count} due to error {str(e)}\n\033[0m")
                    skipped += 1
                    continue

        # Write remaining packets in final batch
        if batch_packets:
            write_batch(batch_packets, output_file)
        
        # Clear the pulsing indicator
        print(f"\r\033[90mLabeling the packets...✓\033[0m")
        print(f"\033[1;92mDone\033[0m")
        print(f"\033[90mThe ground truth file has been saved as {output_file}\033[0m")
        print(f"\033[1;37mProcessed {packet_count} total packets\033[0m")
        print(f"\033[1;37m{skipped} packets have been skipped due to errors or unknown protocols\033[0m")
        print(f"\033[1;37m{unknown} packets have unknown flowIDs and has been labeled as benign\033[0m")
        return
    
    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        return None

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate ground truth .csv file from .pcap and label .csv")
    parser.add_argument('--csv', type=str, required=True, help='Path to the labels .csv file')
    parser.add_argument('--pcap', type=str, required=True, help='Path to the capture .pcap file')
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the output file')
    args = parser.parse_args()
    print("\n\033[1;37mResearch Kit 🔦\n\033[0;90mToN-IoT packet labeler\n\033[0m")

    output_name = input(f"\033[37mOutput file name [ \033[90mwithout .csv\033[37m ] : \033[0m")
    print("\033[90mStarting the computation...\n\033[0m")

    # Load the flows with their labels from the .csv file
    flow_labels = load_flow_labels(args.csv)
    if flow_labels is None:
        print(f"\033[1;91mError 🔥\n\033[0;90mThe .csv file does not contain valid labels\n\033[0m")
    else:
        packet_labeler(flow_labels, args.pcap, output_name, args.destination) 