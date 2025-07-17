import os
import sys
import subprocess
import pandas as pd
import argparse

# Merges multiple CSV files from a folder into a single CSV file
def csv_merge(destination_folder=None):
    try:
        # Get folder containing CSV files
        folder = input("\033[37mFolder containing CSV files [ \033[90mpath\033[37m ] : \033[0m")
        output_name = input("\033[37mOutput file name [ \033[90mwithout .csv\033[37m ] : \033[0m")
        header = input("\033[37mCSV files have header? [ \033[90my or n\033[37m ] : \033[0m").lower()

        # List all CSV files in the folder, sorted alphabetically
        csv_files = sorted([f for f in os.listdir(folder) if f.endswith('.csv')])
        if not csv_files:
            print("\033[91mNo CSV files found in the folder\033[0m")
            return

        # Read headers of the first CSV file only
        first_file = csv_files[0]
        first_file_path = os.path.join(folder, first_file)
        if header == 'y':
            first_df_head = pd.read_csv(first_file_path, header=0, nrows=0, low_memory=False)
        else:
            first_df_head = pd.read_csv(first_file_path, header=None, nrows=0, low_memory=False)
        unique_columns = list(first_df_head.columns)
        # Print numeric list of columns
        print("\033[1;37m\nHeader Arguments 📋\033[0m\n\033[90mExtracted from the first file in alphabetical order\n\033[0m")
        cols_per_line = 3
        col_width = 30  # Adjust as needed for best fit
        for i in range(0, len(unique_columns), cols_per_line):
            line = "".join([f"{idx+1:02d}: {str(col):<{col_width}}" for idx, col in enumerate(unique_columns[i:i+cols_per_line], i)])
            print(f"  {line}")
        # Ask user for columns to include
        selected = input("\033[37m\nArguments selection [ \033[90mlist them separated with a blank space\033[37m ] : \033[0m")
        selected_indices = [int(x)-1 for x in selected.strip().split() if x.isdigit() and 0 < int(x) <= len(unique_columns)]
        selected_columns = [unique_columns[i] for i in selected_indices]
        print(f"\033[90mSelected columns {selected_columns}\033[0m")
        print("\033[90mMerging CSV files...\n\033[0m")
        # Read and concatenate all CSV files, only with selected columns
        dataframes = []
        for file in csv_files:
            file_path = os.path.join(folder, file)
            if header == 'y':
                df = pd.read_csv(file_path, header=0, low_memory=False)
            else:
                df = pd.read_csv(file_path, header=None, low_memory=False)
            # Print file name in white, then newline and print file info in gray
            idx = csv_files.index(file) + 1
            total = len(csv_files)
            print(f"\033[37m[\033[1;37m {idx}\033[0m \033[90mof {total} \033[0m\033[37m]\033[1;37m {file}\033[0m")
            print(f"\033[90mRows [{df.shape[0]}]\n\033[0m")
            # For missing columns, add them as blank and print in requested format
            missing_cols = [col for col in selected_columns if col not in df.columns]
            if missing_cols:
                print(f"\033[1;33mMissing ⚠️\n\033[0m\033[37m: {', '.join(str(col) for col in missing_cols)}\033[0m")
            for col in missing_cols:
                df[col] = ""
            # Only keep selected columns, in the order specified
            df = df[selected_columns]
            dataframes.append(df)
        merged_df = pd.concat(dataframes, ignore_index=True)

        # Determine output folder
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.csv")
        else:
            output_file = f"{output_name}.csv"

        merged_df.to_csv(output_file, index=False, header=(header == 'y'))
        print(f"\033[1;92mDone\033[0m\n\033[90mMerged file saved as {output_file}\033[0m")
        # Print merged file info
        print(f"\033[90mRows [{merged_df.shape[0]}]\nColumns {list(merged_df.columns)}\n\033[0m")
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# Merges multiple PCAP files from a folder into a single PCAP file
def pcap_merge(destination_folder=None):
    try:
        # Get folder containing PCAP files
        folder = input("\033[37mFolder containing PCAP files [ \033[90mpath\033[37m ] : \033[0m")
        output_name = input("\033[37mOutput file name [ \033[90mwithout .pcap\033[37m ] : \033[0m")

        # List all PCAP files in the folder, sorted alphabetically
        pcap_files = sorted([f for f in os.listdir(folder) if f.endswith('.pcap') or f.endswith('.pcapng')])
        if not pcap_files:
            print("\033[91mNo PCAP files found in the folder\033[0m")
            return

        # Check if mergecap is available
        try:
            subprocess.run(['mergecap', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("\033[91mmergecap not found. Please install Wireshark/tshark to use PCAP merging functionality.\033[0m")
            print("\033[90mYou can install it with: sudo apt-get install wireshark-common\033[0m")
            return

        # Pre-process files to remove corrupted packets
        print("\033[90mPre-processing files to remove corrupted packets...\n\033[0m")
        cleaned_files = []
        temp_dir = os.path.join(folder, "temp_cleaned")
        os.makedirs(temp_dir, exist_ok=True)
        
        for idx, file in enumerate(pcap_files, 1):
            file_path = os.path.join(folder, file)
            cleaned_file_path = os.path.join(temp_dir, f"cleaned_{file}")
            print(f"\033[37m[\033[1;37m {idx}\033[0m \033[90mof {len(pcap_files)} \033[0m\033[37m]\033[1;37m {file}\033[0m")
            
            # Use editcap to clean the file (remove corrupted packets)
            try:
                editcap_result = subprocess.run(['editcap', '-F', 'pcap', file_path, cleaned_file_path], 
                                              capture_output=True, text=True)
                if editcap_result.returncode == 0:
                    cleaned_files.append(cleaned_file_path)
                    print(f"\033[90m  Cleaned successfully\033[0m")
                else:
                    print(f"\033[90m  Using original file (cleaning failed)\033[0m")
                    if editcap_result.stderr:
                        print(f"\033[90m    Error: {editcap_result.stderr.strip()}\033[0m")
                    cleaned_files.append(file_path)
            except FileNotFoundError:
                print(f"\033[90m  Using original file (editcap not found)\033[0m")
                cleaned_files.append(file_path)
        
        print("\033[90mMerging PCAP files...\n\033[0m")
        
        # Determine output folder and file
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.pcap")
        else:
            output_file = f"{output_name}.pcap"
        
        # Use cleaned files for merging
        input_files = cleaned_files
        
        # Count packets in cleaned files
        total_packets = 0
        file_packet_counts = {}
        
        print("\033[90mAnalyzing cleaned files...\n\033[0m")
        for idx, file_path in enumerate(cleaned_files, 1):
            file_name = os.path.basename(file_path)
            print(f"\033[37m[\033[1;37m {idx}\033[0m \033[90mof {len(cleaned_files)} \033[0m\033[37m]\033[1;37m {file_name}\033[0m")
            
            # Count packets using capinfos
            try:
                capinfos_result = subprocess.run(['capinfos', '-c', file_path], 
                                               capture_output=True, text=True, check=True)
                # Parse the output: "Number of packets: 8240 k" -> extract "8240 k"
                output_line = capinfos_result.stdout.strip().split('\n')[-1]  # Get last line
                packet_info = output_line.split(':')[1].strip()  # Get "8240 k"
                
                # Handle different formats (e.g., "8240 k", "1234", "1.5 M")
                if 'k' in packet_info.lower():
                    packet_count = int(float(packet_info.lower().replace('k', '')) * 1000)
                elif 'm' in packet_info.lower():
                    packet_count = int(float(packet_info.lower().replace('m', '')) * 1000000)
                else:
                    packet_count = int(packet_info)
                
                file_packet_counts[file_name] = packet_count
                total_packets += packet_count
                print(f"\033[90mPackets [{packet_count:,}]\n\033[0m")
            except (subprocess.CalledProcessError, ValueError, IndexError) as e:
                print(f"\033[90mPackets [Unable to count]\n\033[0m")
                file_packet_counts[file_name] = 0
        
        print(f"\033[90m\nTotal packets before merge: {total_packets:,}\033[0m")
        print("\033[90mMerging PCAP files...\n\033[0m")
        
        # Use mergecap to merge all files at once
        merge_cmd = ['mergecap', '-w', output_file] + input_files
        result = subprocess.run(merge_cmd, capture_output=True, text=True)
        
        # Check if mergecap completed successfully
        if result.returncode == 0:
            print(f"\033[1;92mDone\033[0m\n\033[90mMerged file saved as {output_file}\033[0m")
            print(f"\033[90mTotal files merged: {len(pcap_files)}\033[0m")
            
            # Count packets in merged file
            try:
                capinfos_result = subprocess.run(['capinfos', '-c', output_file], 
                                               capture_output=True, text=True, check=True)
                # Parse the output: "Number of packets: 8240 k" -> extract "8240 k"
                output_line = capinfos_result.stdout.strip().split('\n')[-1]  # Get last line
                packet_info = output_line.split(':')[1].strip()  # Get "8240 k"
                
                # Handle different formats (e.g., "8240 k", "1234", "1.5 M")
                if 'k' in packet_info.lower():
                    merged_packet_count = int(float(packet_info.lower().replace('k', '')) * 1000)
                elif 'm' in packet_info.lower():
                    merged_packet_count = int(float(packet_info.lower().replace('m', '')) * 1000000)
                else:
                    merged_packet_count = int(packet_info)
                
                print(f"\033[90mMerged file packets: {merged_packet_count:,}\033[0m")
                
                # Show packet loss if any
                if merged_packet_count != total_packets:
                    packet_loss = total_packets - merged_packet_count
                    print(f"\033[93mPacket loss: {packet_loss:,} packets\033[0m")
                else:
                    print(f"\033[90mNo packet loss detected\033[0m")
                    
            except (subprocess.CalledProcessError, ValueError, IndexError):
                print(f"\033[90mUnable to count packets in merged file\033[0m")
            
            print("\033[0m")
        else:
            # Handle warnings about truncated files
            if "appears to have been cut short" in result.stderr or "truncated" in result.stderr.lower():
                print(f"\033[93m\n\033[1mWarning\033[0m\033[93m ⚠️\n\033[0m\033[90m Some PCAP files appear to be truncated, but merging completed\n\033[0m")
                print(f"\033[90mMerged file saved as {output_file}\033[0m")
                if result.stderr:
                    print(f"\033\n[90m{result.stderr.strip()}\033\n[0m")
            else:
                # Handle other errors
                print(f"\033[91mError during merge:\033[0m")
                if result.stderr:
                    print(f"\033[90m{result.stderr.strip()}\033[0m")
                if result.stdout:
                    print(f"\033[90m{result.stdout.strip()}\033[0m")
        
        # Clean up temporary directory
        try:
            import shutil
            shutil.rmtree(temp_dir)
            print(f"\033[90mCleaned up temporary files\033[0m")
        except:
            pass
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# Main merger function with menu
def merger(destination_folder=None):
    print("1. PCAP files")
    print("2. CSV files")
    
    choice = input("\033[37mSelect option [ \033[90m1 or 2\033[37m ] : \033[0m").strip()
    
    if choice == '1':
        print("\033[1;37m\nPCAPs Merge 🦈\033[0m\033[90m\nUsing mergecap by The Wireshark Team\n\033[0m")
        pcap_merge(destination_folder)
    elif choice == '2':
        print("\033[1;37m\nCSVs Merge 📊\033[0m\033[90m\n\033[0m")
        csv_merge(destination_folder)
    else:
        print("\033[91mInvalid option. Please select 1 or 2.\033[0m")

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge multiple CSV or PCAP files from a folder into a single file")
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the merged file')
    args = parser.parse_args()
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mFile Merger\n\033[0m")
    merger(destination_folder=args.destination)
