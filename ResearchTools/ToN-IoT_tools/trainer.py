# trainer.py
# Sample N packets from a .pcap file for training purposes
# Author : Dario Crippa [ AstroWLAN ]

# IMPORTS
import os
import argparse
import numpy as np
from scapy.utils import PcapReader, PcapWriter

# MAIN
def main():
    parser = argparse.ArgumentParser(description="Sample N packets from a .pcap file, preserving order.")
    parser.add_argument('-i', type=str, required=True, help='Input .pcap file')
    parser.add_argument('-o', type=str, required=True, help='Output .pcap file')
    parser.add_argument('-n', type=int, default=55000, help='Number of packets to sample - default: 55000')
    args = parser.parse_args()

    # Input file verification
    if not os.path.isfile(args.input):
        print(f"\033[1;91mError 🔥\n\033[0;90mInput file does not exist: {args.input}\n\033[0m")
        exit(1)
    if not args.input.lower().endswith('.pcap'):
        print(f"\033[1;91mError 🔥\n\033[0;90mInput file must be a .pcap file\n\033[0m")
        exit(1)

    print(f"\n\033[1;37mTON-IoT Kit 📀\n\033[0;90mCollect {args.num} packets for training purposes\n\033[0m")

    # Read all packets and their timestamps
    packets = []
    with PcapReader(args.input) as pcap_reader:
        for pkt in pcap_reader:
            packets.append(pkt)
    total_packets = len(packets)
    print(f"\033[90mTotal packets in input: {total_packets}\033[0m")

    if args.num > total_packets:
        print(f"\033[1;91mError 🔥\n\033[0;90mRequested {args.num} packets, but input only has {total_packets}\n\033[0m")
        exit(1)

    # Get timestamps and sort packets by timestamp (if not already sorted)
    packets = sorted(packets, key=lambda pkt: getattr(pkt, 'time', 0))

    # Sample N unique indices
    sampled_indices = np.random.choice(total_packets, args.num, replace=False)
    sampled_indices.sort()  # To preserve order

    # Write sampled packets to output
    with PcapWriter(args.output, append=False, sync=True) as writer:
        for idx in sampled_indices:
            writer.write(packets[idx])

    print(f"\033[1;92mDone\033[0m\n\033[90mSampled {args.num} packets written to {args.output}\033[0m")

if __name__ == "__main__":
    main() 