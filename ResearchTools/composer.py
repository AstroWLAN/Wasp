# MODULES
import os
import csv
from pathlib import Path

# Generates a single .csv file with aggregate information about labels and flowIDs
def composer(): 
    # PARAMETERS [ default values from other scripts ]
    desktop = str(Path.home() / "Desktop")
    col_predictions = 0
    col_flowIDs = 1
    col_TL = 0
    
    # Gets the .csv file paths and the attack name
    kitNET_predictions = input("KitNET predictions and flowIDs [ \033[90m.csv path\033[0m ] : ")
    TL = input("True labels [ \033[90m.csv path\033[0m ] : ")
    attack = input("Attack : ")
    output = os.path.join(desktop, f"{attack}_aggregated_info.csv")
    
    # Processes the .csv files
    print("\033[90mAggregating information\033[0m")
    try:
        with open(kitNET_predictions, 'r') as kitnet_file, \
             open(TL, 'r') as tl_file, \
             open(output, 'w', newline='') as output:
            kitnet_reader = csv.reader(kitnet_file)
            tl_reader = csv.reader(tl_file)
            writer = csv.writer(output)
            writer.writerow(['FlowIDs', 'KitNet Predictions', 'True Labels'])
            next(kitnet_reader)
            next(tl_reader)
            for kitnet_row, tl_row in zip(kitnet_reader, tl_reader):
                flow_id = kitnet_row[col_flowIDs]
                prediction = kitnet_row[col_predictions]
                true_label = tl_row[col_TL]
                writer.writerow([flow_id, prediction, true_label])
        print(f"\033[92mDone\033[0m")
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mDataset composer\n\033[0m")
    composer() 