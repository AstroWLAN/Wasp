# Merger.py 
# Merge multiple .csv or .pcap files from a folder into a single file 
# This script was created to adapt popular datasets such as TON-IoT to KitNET, but it can be easily adapted to other datasets
# Author : Dario Crippa [ AstroWLAN ]

# IMPORTS
import os
import shutil
import argparse
import subprocess
import pandas as pd

# Merge all .csv files in the specified folder into a single consolidated .csv file
# Add a flowID column to the output file header
# Note: CSV files must have headers containing the required field names
def csv_merging(input_folder=None, destination_folder=None):
    try:
        # Retrieve the input folder if it has not been provided as a parameter
        if input_folder is None:
            folder = input("\033[37mFolder containing .csv files [ \033[90mpath\033[37m ] : \033[0m")
        else:
            folder = input_folder
        
        # Name of the output .csv file
        output_name = input("\033[37mOutput file name [ \033[90mwithout .csv\033[37m ] : \033[0m")

        # List all .csv files in the folder and sort them alphabetically 
        # TIP : use zero-padded numbering to ensure proper sorting
        files = sorted([f for f in os.listdir(folder) if f.endswith('.csv')])
        if not files:
            print(f"\033[91mError 🔥\n\033[90mThere are no .csv files in the folder\n\033[0m")
            return

        # Required fields for the flowID generation
        required_fields = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto']

        # Read and concatenate all .csv files
        dataframes = []
        expected_rows = 0  
        print("\033[90mReading the .csv files...\n\033[0m")
        
        for file in files:
            file_path = os.path.join(folder, file)
            try:
                # The .csv files must have headers that contain the required field names
                df = pd.read_csv(file_path, header=0, low_memory=False)
                
                # Check if the required fields are present in the current file
                missing_required = [field for field in required_fields if field not in df.columns]
                if missing_required:
                    raise Exception(f"One or more required fields are missing in {file}")
                
                # Log some information about the current file
                print(f"∗ \033[1;37m{files.index(file) + 1}\033[0;90m of {len(files)}\033[37m \033[1;37m {file}\033[0m")
                print(f"\033[90mThis file contains {df.shape[0]} rows\n\033[0m")
                
                # Add the current file's row count to the total expected rows
                expected_rows += df.shape[0]
                
                # Create the flowID column by concatenating the required fields
                df['flowID'] = df['src_ip'].astype(str) + '_' + df['src_port'].astype(str) + '_' + df['dst_ip'].astype(str) + '_' + df['dst_port'].astype(str) + '_' + df['proto'].astype(str)
                
                dataframes.append(df)
                
            except Exception as error:
                raise Exception(f"An error occurred while processing the file {file} : {str(error)}")

        # Concatenate all dataframes into a single dataframe
        print("\033[90mConcatenating the .csv files...\033[0m")
        merged_df = pd.concat(dataframes, ignore_index=True)

        # Output the merged .csv file
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.csv")
        else:
            output_file = f"{output_name}.csv"

        print("\033[90mSaving the dataframe as a .csv file...\033[0m")
        merged_df.to_csv(output_file, index=False, header=True)

        # Log the output file information
        print(f"\033[1;92mDone\033[0m\n\033[0;37mMerged file saved as {output_file}\033[0m")
        if expected_rows != merged_df.shape[0]:
            print(f"\033[93mWarning ⚠️\n\033[90mThe final size of the merged .csv file is different from the expected size\n\033[0m")
        else:
            print(f"\033[90mThe size of the merged .csv file is the same as the expected one of {expected_rows} rows\033[0m")
    # Exception handling : log the error in the console 
    # Exceptions propagete from the inner to the outer level
    except Exception as error:
        print(f"\033[91mError 🔥\n\033[90m{str(error)}\n\033[0m")

# Merge all .pcap files in the specified folder into a single consolidated .pcap file using mergecap
# It performs some sanitization to remove corrupted, truncated or otherwise invalid packets using editcap
def pcap_merging(input_folder=None, destination_folder=None):
    try:
        # Retrieve the input folder if it has not been provided as a parameter
        if input_folder is None:
            folder = input("\033[37mFolder containing .pcap files [ \033[90mpath\033[37m ] : \033[0m")
        else:
            folder = input_folder
        
        # Name of the output .pcap file
        output_name = input("\033[37mOutput file name [ \033[90mwithout .pcap\033[37m ] : \033[0m")

        # List all .pcap files in the folder and sort them alphabetically 
        # TIP : use zero-padded numbering to ensure proper sorting
        pcap_files = sorted([f for f in os.listdir(folder) if f.endswith('.pcap') or f.endswith('.pcapng')])
        if not pcap_files:
            print(f"\033[91mError 🔥\n\033[90mThere are no .pcap files in the folder\n\033[0m")
            return

        # Ensure that mergecap is available in the system
        try:
            subprocess.run(['mergecap', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"\033[91mError 🔥\n\033[90mMergecap not found\nYou can install it with: sudo apt-get install wireshark-common\n\033[0m")
            return

        # Sanitize the .pcap files to remove corrupted or truncated packets
        print("\033[90mSanitizing the .pcap files...\n\033[0m")
        sanitized_pcap = []
        temp_dir = os.path.join(folder, "sanitized_temp_folder")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Sanitize the files using editcap
        for idx, file in enumerate(pcap_files, 1):
            file_path = os.path.join(folder, file)
            cleaned_file_path = os.path.join(temp_dir, f"cleaned_{file}")
            print(f"∗ \033[1;37m{idx}\033[0;90m of {len(pcap_files)}\033[37m \033[1;37m {file}\033[0m")
            try:
                editcap_result = subprocess.run(['editcap', '-F', 'pcap', file_path, cleaned_file_path], capture_output=True, text=True)
                if editcap_result.returncode == 0:
                    sanitized_pcap.append(cleaned_file_path)
                    print(f"\033[90mThis .pcap file has been sanitized\n\033[0m")
                else:
                    print(f"\033[90mCleaning failed : using the original file\n\033[0m")
                    if editcap_result.stderr:
                        print(f"\033[91mError 🔥\n\033[90m{editcap_result.stderr.strip()}\n\033[0m")
                    sanitized_pcap.append(file_path)
            # FileNotFoundError is the specific exception raised when Python cannot find the executable command in the system's PATH 
            except FileNotFoundError:
                print(f"\033[90mUsing the original file since editcap has not been found\033[0m")
                sanitized_pcap.append(file_path)
        
        # Output the merged .pcap file
        if destination_folder:
            os.makedirs(destination_folder, exist_ok=True)
            output_file = os.path.join(destination_folder, f"{output_name}.pcap")
        else:
            output_file = f"{output_name}.pcap"
        
        # Use the sanitized files for merging
        input_files = sanitized_pcap
        
        print("\033[90mMerging PCAP files...\033[0m")
        # Use mergecap to merge all the .pcap files at once
        merge_cmd = ['mergecap', '-w', output_file] + input_files
        result = subprocess.run(merge_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            # Log the output file information
            print(f"\033[1;92mDone\033[0m\n\033[0;37mMerged file saved as {output_file}\033[0m")   
        else:
            # Handle warnings
            if "appears to have been cut short" in result.stderr or "truncated" in result.stderr.lower():
                print(f"\033[93mWarning ⚠️\n\033[90mSome packets appear to be truncated or corrupted but merging step has been completed\n\033[0m")
                print(f"\033[90mMerged file saved as {output_file}\n\033[0m")
            else:
                # Handle catastrophic failures
                print(f"\033[91mError 🔥\n\033[90mFailed to merge .pcap files\n\033[0m")
                if result.stderr:
                    print(f"\033[90m{result.stderr.strip()}\033[0m")
        
        # Clean up the temporary folder containing the sanitized files
        try:
            shutil.rmtree(temp_dir)
        except:
            pass
        
    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[91mError 🔥\n\033[90m{str(error)}\n\033[0m")

# Menu to choose the merging method
def merger(input_folder=None, destination_folder=None):
    print("1. Merge .pcap files")
    print("2. Merge .csv files")
    
    # User choice
    choice = input("\033[37mSelect option [ \033[90m1 or 2\033[37m ] : \033[0m").strip()
    
    if choice == '1':
        print("\033[1;37m\nMerge .pcap files 🦈\n\033[0;90mBuilt on top of mergecap by The Wireshark Team\n\033[0m")
        pcap_merging(input_folder, destination_folder)
    elif choice == '2':
        print("\033[1;37m\nMerge .csv files 📄\n\033[0m")
        csv_merging(input_folder, destination_folder)
    else:
        print("\033[91mInvalid option. Please select 1 or 2.\033[0m")

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge multiple files from a folder into a single file")
    parser.add_argument('-i', '--input', type=str, help='Input folder containing the files to merge')
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the merged file')
    args = parser.parse_args()
    print("\n\033[1;37mResearch Kit 🔦\n\033[0;90mFile Merger\n\033[0m")
    merger(input_folder=args.input, destination_folder=args.destination)
