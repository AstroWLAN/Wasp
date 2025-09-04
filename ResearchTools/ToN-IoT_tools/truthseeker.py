# truthseeker.py
# Generate training .pcap file using probabilistic sampling from original .pcap
# Uses the same probabilistic_sampling approach as sampling.py
# Target : TON-IoT dataset https://research.unsw.edu.au/projects/toniot-datasets
# Author : Dario Crippa [ AstroWLAN ]

# IMPORTS
import os
import argparse
import numpy as np
from scapy.utils import PcapReader, PcapWriter
from sampling import probabilistic_sampling


# Sample packets from a .pcap file using probabilistic sampling and create a training .pcap file
def packet_sampler(pcap_path, output_name, num_samples, destination_folder=None):
    try:
        # File existence check
        if not os.path.isfile(pcap_path):
            print(f"\033[1;91mError 🔥\n\033[0;90mThe .pcap file at {pcap_path} does not exist\n\033[0m")
            return
        # Format check : is the file a .pcap or .pcapng file?
        if not pcap_path.endswith(('.pcap', '.pcapng')):
            print(f"\033[1;91mError 🔥\n\033[0;90mThe file {pcap_path} is not a .pcap or .pcapng file\n\033[0m")
            return

        print("\033[90mCounting total packets in .pcap file...\033[0m")

        # First pass: count total packets (M)
        total_packets = 0
        with PcapReader(pcap_path) as pcap_reader:
            for _ in pcap_reader:
                total_packets += 1

        print(f"\033[1;37mTotal packets (M): {total_packets}\033[0m")
        print(f"\033[1;37mTarget samples (N): {num_samples}\033[0m")

        if num_samples > total_packets:
            print(f"\033[1;93mWarning ⚠️\n\033[0;90mRequested {num_samples} samples but only {total_packets} packets available. Using all packets.\033[0m")
            num_samples = total_packets

        # Calculate sampling rate
        sampling_rate = num_samples / total_packets
        print(f"\033[1;37mSampling rate: {sampling_rate:.6f}\033[0m")

        # Generate sampling mask
        print("\033[90mGenerating probabilistic sampling mask...\033[0m")
        sampling_mask = probabilistic_sampling(sampling_rate, total_packets)

        # Establish the output file path
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}_training.pcap")
        else:
            output_file = f"{output_name}_training.pcap"

        print("\033[90mCollecting sampled packets...\033[0m", end="", flush=True)

        # Second pass: collect sampled packets
        sampled_packets = []
        packet_index = 0
        processed_packets = 0

        with PcapReader(pcap_path) as pcap_reader:
            for packet in pcap_reader:
                processed_packets += 1

                # Update pulsing indicator every 1000 packets
                if processed_packets % 1000 == 0:
                    symbols = [" ", "*", " ", "*"]
                    symbol = symbols[(processed_packets // 1000) % len(symbols)]
                    print(f"\r\033[90mCollecting sampled packets...{symbol}\033[0m", end="", flush=True)

                # Check if this packet should be sampled
                if sampling_mask[packet_index]:
                    sampled_packets.append(packet)

                packet_index += 1

        # Sort sampled packets by timestamp
        print(f"\r\033[90mSorting {len(sampled_packets)} sampled packets by timestamp...\033[0m")
        sampled_packets.sort(key=lambda pkt: pkt.time)

        # Write sampled packets to new .pcap file
        print(f"\033[90mWriting training .pcap file...\033[0m")
        with PcapWriter(output_file) as pcap_writer:
            for packet in sampled_packets:
                pcap_writer.write(packet)

        print(f"\033[1;92mDone\033[0m")
        print(f"\033[90mTraining .pcap file saved as: {output_file}\033[0m")
        print(f"\033[1;37mOriginal packets (M): {total_packets}\033[0m")
        print(f"\033[1;37mSampled packets (N): {len(sampled_packets)}\033[0m")
        print(f"\033[1;37mActual sampling rate: {len(sampled_packets)/total_packets:.6f}\033[0m")
        return

    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        return None

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate training .pcap file using probabilistic sampling from original .pcap")
    parser.add_argument('--pcap', type=str, required=True, help='Path to the input .pcap file')
    parser.add_argument('--samples', type=int, required=True, help='Number of packets to sample (N)')
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the output file')
    args = parser.parse_args()

    print("\n\033[1;37mResearch Kit 🔦\n\033[0;90mToN-IoT probabilistic packet sampler\n\033[0m")
    print(f"\033[1;37mInput .pcap: {args.pcap}\033[0m")
    print(f"\033[1;37mTarget samples: {args.samples}\033[0m")

    output_name = input(f"\033[37mOutput file name [ \033[90mwithout _training.pcap\033[37m ] : \033[0m")
    print("\033[90mStarting probabilistic sampling...\n\033[0m")

    # Perform probabilistic sampling and generate training .pcap
    packet_sampler(args.pcap, output_name, args.samples, args.destination) 