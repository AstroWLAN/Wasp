import os
import sys
import pandas as pd
import argparse

# Merges multiple CSV files from a folder into a single CSV file
def merger(destination_folder=None):
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
            print(f"\033[37m[\033[1;37m{idx}\033[37m of \033[90m{total}\033[37m]\033[1;37m {file}\033[0m")
            print(f"\033[90mRows [{df.shape[0]}]\n\033[0m")
            # For missing columns, add them as blank and print in requested format
            missing_cols = [col for col in selected_columns if col not in df.columns]
            if missing_cols:
                print(f"\033[1;33mMissing ⚠️ \033[0m\033[37m: {', '.join(str(col) for col in missing_cols)}\033[0m")
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

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge multiple CSV files from a folder into a single CSV file")
    parser.add_argument('-d', '--destination', type=str, help='Destination folder for the merged CSV file')
    args = parser.parse_args()
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mCSV Merger\n\033[0m")
    merger(destination_folder=args.destination)
