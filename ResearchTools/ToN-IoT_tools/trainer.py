from scapy.all import *
import os
import random

# Generate training .pcap file with N consecutive packets starting from a seeded random position
def trainer():
    try:
        # User inputs
        pcap = input("\033[37mFile [ \033[90m.pcap \033[37m] : \033[0m")
        n_packets_input = input("\033[37mPackets for training \033[0m[ \033[90mdefault value is 55000\033[0m ] : ").strip()
        seed_input = input("\033[37mSeed for random starting point \033[0m[ \033[90mdefault value is 42\033[0m ] : ").strip()

        # Set defaults
        if not n_packets_input:
            n_packets = 55000
        else:
            n_packets = int(n_packets_input)

        if not seed_input:
            seed = 42
        else:
            seed = int(seed_input)

        print("\033[90mGenerating training .pcap file...\033[0m")

        # Read the .pcap file
        packets = rdpcap(pcap)
        total_packets = len(packets)
        print(f"\033[90mThere are {total_packets} packets in the input .pcap file\033[0m\n")

        if n_packets >= total_packets:
            raise Exception(f"Requested {n_packets} packets but only {total_packets} packets available")

        # Use seed to determine starting point
        random.seed(seed)
        max_start = total_packets - n_packets
        start_index = random.randint(0, max_start)
        end_index = start_index + n_packets

        print(f"\033[90mUsing seed {seed}, starting at packet index {start_index}\033[0m")
        print(f"\033[90mExtracting packets {start_index} to {end_index-1}\033[0m\n")

        # Extract consecutive packets
        training_packets = packets[start_index:end_index]

        # Output filename -> save to the input folder
        input_dir = os.path.dirname(os.path.abspath(pcap))
        training_file = os.path.join(input_dir, "clean_training.pcap")

        # Write the .pcap file
        wrpcap(training_file, training_packets)

        print("\033[1;92mDone\033[0m")
        print(f"\033[90mTraining .pcap file saved as {training_file}\033[0m\n")

    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mToN-IoT Training Data Generator\n\033[0m")
    trainer()
