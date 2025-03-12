# MODULES
import os
import time
import numpy as np
import pandas as pd
from Kitsune import Kitsune
from ResearchTools import tools
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn

# PARAMETERS
# Gets the folder where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
# Limits to the number of packets to process [ useless tho... ]
packet_limit = np.inf
# KitNET settings
# Maximum number of AutoEncoders in the ensemble layer
max_AutoEncoders = 10
# Training must be done on clean traffic [ Mirai.pcap first 70K packets are fine ]
# Grace period is the sum of the packets used to train the feature mapping [ FM ] and the anomaly detector [ AD ]
FM_grace = 5000
AD_grace = 50000
# Packet index
current_packet = 0
# True labels
true_labels = None
# Sampling labels 
predicted_labels = []

# Customizes the appearance of TimeElapsedColumn in rich.progress
class WhiteTimeElapsedColumn(TimeElapsedColumn):
    def render(self, task):
        elapsed_text = super().render(task)
        elapsed_text.style = "white"
        return elapsed_text
# Configures the progress bars
custom_columns = [
    TextColumn("[white]{task.description}"),
    WhiteTimeElapsedColumn(),
    BarColumn(),
    TextColumn("[white]{task.percentage:>3.0f}%"),
]

# Loads the TL [ true labels ] from a .csv file
def load_TL():
    # Retrieves the file
    default_TL_path = os.path.join(script_dir, "mirai_true_labels.csv")
    TL_path = input(f"\033[97mEnter .csv path for true labels \033[90m[default: {default_TL_path}]\033[97m : \033[0m")
    if not TL_path.strip():
        # Default path [ pressed ENTER ]
        print("\033[90mDefault option selected 📐\033[0m")
        TL_path = default_TL_path
    if not os.path.exists(TL_path):
        # Verifies the file exists
        print("\033[91mFile not found 🔥\033[0m\n\033[90mPlease provide a valid file\033[0m")
        return
    
    # Mirai TL [ it is different from the other datasets ]
    if TL_path == default_TL_path:
        TL_dataframe = pd.read_csv(TL_path, header=None, low_memory=False)
        # Convert the values to the appropriate type
        true_labels = TL_dataframe.iloc[:, 0].values
        # Remove the packets used for training
        true_labels = true_labels[FM_grace + AD_grace:]
    # Other datasets in the Kaggle repo [ https://www.kaggle.com/datasets/ymirsky/network-attack-dataset-kitsune ]
    else: 
        # Loads and sanitizes the true labels [ removes the packets used for the training ]
        TL_dataframe = pd.read_csv(TL_path, header=0, low_memory=False)
        # Consider only the second column (index 1) since the first row is the header
        TL_dataframe = TL_dataframe.iloc[:, 1:2]
        # Convert the values to the appropriate type
        true_labels = TL_dataframe.iloc[:, 0].values
        # Remove the packets used for training
        true_labels = true_labels[FM_grace + AD_grace:]
    
    return true_labels

# Loads the predictions from a .csv file
def load_predictions(true_labels, wasps = False):
    # Retrieves the file
    default_path = os.path.expanduser("~/Desktop/predicted_mirai_packets.csv")
    csv_path = input(f"\033[97mEnter predictions .csv file path \033[90m[ default at {default_path} ]\033[97m : \033[0m")
    if not csv_path.strip():
         # Default path [ pressed ENTER ]
        print("\033[90mDefault option selected 📐\033[0m")
        csv_path = default_path
    # Verifies the file exists
    if not os.path.exists(csv_path):
        print("\033[91mThis file does not exist 🔥\033[0m\n\033[90mProvide a valid file\n\033[0m")
        return None, None
    try:
        # Loads the predictions 
        predictions_df = pd.read_csv(csv_path)
        # Verifies that the 'predictions' column exists in the dataframe
        if 'predictions' not in predictions_df.columns:
            print("\033[91mThe provided .csv file does not contain valid predictions 🔥\033[90mProvide the required information\033[0m")
            return None, None
        predictions = np.array(predictions_df['predictions'])
        
        if wasps:
            # Loads the flowIDs if required
            if 'flowID' not in predictions_df.columns:
                print("\033[91mThe provided .csv file does not contain valid flowIDs 🔥\033[90mProvide the required information\033[0m")
                return None, None
            flowIDs = np.array(predictions_df['flowID'])
            print(f"\033[90mLoaded {len(predictions)} predictions and {len(flowIDs)} flowIDs for {len(true_labels)} true labels\033[0m\n")
            return predictions, flowIDs
        
        print(f"\033[90mLoaded {len(predictions)} predictions for {len(true_labels)} true labels\033[0m\n")
        return predictions, None
    
    except pd.errors.EmptyDataError:
        print("\033[91mThe .csv file is empty 🔥\033[0m\n")
        return None, None
    except pd.errors.ParserError:
        print("\033[91mThe file is not a valid .csv 🔥\033[0m\n")
        return None, None
    except Exception as e:
        print(f"\033[91mGeneric Error 🔥\033[0m\n\033[90m{str(e)}\033[0m\n")
        return None, None
    
# Builds the original version of Kitsune
def run_kitsune():
    global current_packet, true_labels, predicted_labels
    # Resets the global variables and loads the true labels
    current_packet = 0
    predicted_labels = []
    true_labels = load_TL()
    # Loads a .pcap file
    default_pcap_path = os.path.join(script_dir, "mirai_packets.pcap")
    pcap_path = input(f"\033[97mEnter .pcap file path \033[90m[default: {default_pcap_path}]\033[97m : \033[0m")  
    if not pcap_path.strip():
        # Default path [ pressed ENTER ]
        print("\033[90mDefault option selected 📐\033[0m")
        pcap_path = default_pcap_path
    if not os.path.exists(pcap_path):
        # Verifies that the file exists
        print("\033[91mFile not found 🔥\033[0m\n\033[90mPlease provide a valid file\033[0m")
        return
    
    # Runs Kitsune
    print("\n\033[97mRunning Kitsune 🔍\033[0m")
    kitsune = Kitsune(pcap_path, packet_limit, max_AutoEncoders, FM_grace, AD_grace)
    start = time.time()
    # Processes the packets and visualizes the progress bars
    with Progress(*custom_columns) as progress:
        # Generates a task for each Kitsune phase
        FM_task = progress.add_task("FM Training", total=FM_grace)
        AD_task = progress.add_task("AD Training", total=AD_grace, visible=False)
        try:
            # Retrieves the number of packets extracted from the .pcap file
            total_packets = len(kitsune.FE.packets)
            # Computes the total number of packets to be processed in the detection phase [ tot. packets - packets used for the training phases ]
            detection_packets = total_packets - FM_grace - AD_grace
            if detection_packets <= 0:
                print("\033[93mNo packets left to process after training 📣\033[0m\n")  
                return
            DE_task = progress.add_task("Detection", total=detection_packets, visible=False)
        except (AttributeError, TypeError):
            print("\033[91mDetection task creation failed 🔥\033[0m\n")  
            return
            
        while True:
            current_packet += 1
            # Starts the analysis of the following packet
            rmse, flowID = kitsune.process_packet()
            if rmse == -1 and flowID is None:
                # Non-valid RMSE...
                break
            # Updates the progress bar 
            if current_packet <= FM_grace:
                progress.update(FM_task, completed=current_packet)
                if current_packet == FM_grace:
                    # Makes the AD training progress bar visible
                    progress.update(AD_task, visible=True)      
            elif current_packet <= FM_grace + AD_grace:
                progress.update(AD_task, completed=current_packet - FM_grace)
                if current_packet == FM_grace + AD_grace:
                    # Makes the detection progress bar visible
                    progress.update(DE_task, visible=True)     
            else:
                detection_progress = current_packet - FM_grace - AD_grace
                progress.update(DE_task, completed=detection_progress)
                # Predicts the nature of the packets after the training phases
                if rmse >= kitsune.AnomDetector.threshold:
                    # Stores the prediction and the flowID of the packet as a tuple
                    # [ Malicious ]
                    predicted_labels.append((1, flowID))
                else:
                    # [ Benign ]
                    predicted_labels.append((0, flowID))  
                    
    stop = time.time()
    print(f"\033[90mElapsed time: {stop - start:.6f} seconds\033[0m")
    print(f"\033[90mKitsune has made {len(predicted_labels)} predictions for {len(true_labels)} true labels\033[0m")
    # Saves the predicted labels in an external .csv file for further processing
    pcap_filename = os.path.basename(pcap_path)
    pcap_name_without_ext = pcap_filename.replace('.pcap', '')
    desktop_path = os.path.expanduser("~/Desktop")
    csv_filename = f"predicted_{pcap_name_without_ext}.csv"
    csv_path = os.path.join(desktop_path, csv_filename)
    pd.DataFrame(predicted_labels, columns=['predictions', 'flowID']).to_csv(csv_path, index=False)
    print(f"\033[90mSaved predicted labels to [{csv_path}]\033[0m")  
    print("\033[92mDone!\033[0m\n")

# MAIN
if __name__ == "__main__":
    print("\n\033[38;5;214mKitsune 🦊\033[0m")
    print("\033[90mSelect an option to continue\n\033[0m")
    
    # Menu
    while True:
        print("\033[97m1. Standard Kitsune\033[0m")
        print("\033[97m2. Sampling and Wasp Detection\033[0m")
        print("\033[97m3. Quit\033[0m")
        user_choice = input("\n\033[97mInsert your choice \033[90m[ 1-3 ]\033[97m : \033[0m")
        
        # Validates the user input
        if user_choice not in ["1", "2", "3"]:
            print("\033[91mInvalid choice 🔥\033[0m\n\033[90mPlease enter a valid number in the range\n\033[0m")
            continue
        
        # Runs the original version ofKitsune and saves the predicted labels in an external .csv file for further processing
        if user_choice == "1":
            run_kitsune()
            
        # Compares the performance of our experimental architectures [ Sampling and Wasp Detection ]
        elif user_choice == "2":
            # Loads the true labels
            true_labels = load_TL()
            # Loads the prediction generated during the execution of Kitsune
            predictions, flowIDs = load_predictions(true_labels, wasps = True)
            if predictions is None or flowIDs is None:
                print("\033[91mError loading the predictions or the flowIDs 🔥\033[0m\n\033[90mProvide valid data\033[0m\n")
                continue
            tools.benchmark(predictions, flowIDs, true_labels)
        
        # Quits the program
        elif user_choice == "3":
            print("\033[90mGoodbye Friend 🤖\n\033[0m")
            break
