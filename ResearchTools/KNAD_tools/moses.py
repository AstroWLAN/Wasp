from scapy.all import *
import os

# Split a single .pcap file into training and execution .pcap files
def moses():
    try:
        # User inputs
        pcap = input("\033[37mFile [ \033[90m.pcap \033[37m] : \033[0m")
        attack = input("Attack : ").lower()
        n_packets_input = input("\033[37mPackets for training \033[0m[ \033[90mdefault value is 55000\033[0m ] : ").strip()

        # Set default N to 55000 if not provided
        if not n_packets_input:
            n_packets = 55000
        else:
            n_packets = int(n_packets_input)

        print("\033[90mSplitting the .pcap file...\033[0m")

        # Read the .pcap file
        packets = rdpcap(pcap)
        total_packets = len(packets)
        print(f"\033[90mThere are {total_packets} packets in the input .pcap file\033[0m\n")

        if n_packets >= total_packets:
            raise Exception(f"Requested {n_packets} packets but only {total_packets} packets available")

        # Output filenames -> save to the input folder
        input_dir = os.path.dirname(os.path.abspath(pcap))
        training_file = os.path.join(input_dir, f"{attack}_training.pcap")
        execution_file = os.path.join(input_dir, f"{attack}_execution.pcap")

        # Split the packets
        training_packets = packets[:n_packets]
        execution_packets = packets[n_packets:]

        # Write the .pcap files
        wrpcap(training_file, training_packets)
        wrpcap(execution_file, execution_packets)

        print("\033[1;92mDone\033[0m")
        print(f"\033[90mOutput .pcap files saved to {input_dir}\033[0m\n")

    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mKNAD .pcap files splitter\n\033[0m")
    moses()
