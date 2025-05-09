# MODULES
import os
import time
import numpy as np
import pandas as pd
from Kitsune.Kitsune import Kitsune
from ResearchTools import tools
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn

# PARAMETERS
# Gets the folder where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
# Resource directory for pcap and csv files
resource_dir = os.path.join(script_dir, "Resources")
# Limits to the number of packets to process [ useless tho... ]
packet_limit = np.inf
# KitNET settings
# Maximum number of AutoEncoders in the ensemble layer
max_AutoEncoders = 10
# Training must be done on clean traffic [ Mirai.pcap first 70K packets are fine ]
# Grace period is the sum of the packets used to train the feature mapping [ FM ] and the anomaly detector [ AD ]
FM_grace = 5000
AD_grace = 50000

# Customizes the appearance of TimeElapsedColumn in rich.progress
class WhiteTimeElapsedColumn(TimeElapsedColumn):
    def render(self, task):
        elapsed_text = super().render(task)
        elapsed_text.style = "white"
        return elapsed_text
custom_columns = [
    # Configures the progress bars
    TextColumn("[white]{task.description}"),
    WhiteTimeElapsedColumn(),
    BarColumn(),
    TextColumn("[white]{task.percentage:>3.0f}%"),
]

# Loads the TL from a .csv file [ remember to prepare the dataset with the research tools! ]
def load_TL():
    # Retrieves the .csv file path
    TL_path = input("\nTrue labels [\033[90m.csv path\033[0m] : ")
    print("\033[90mLoading the true labels\033[0m")
    try:
        # Loads the true labels from the first column of the .csv file
        dataframe = pd.read_csv(TL_path, header=0)
        TL = np.array(dataframe.iloc[:, 0])
        # Removes the training packets [ FM + AD grace period ]
        TL = TL[(FM_grace + AD_grace):]
        print(f"\033[90mLoaded {len(TL)} true labels\033[0m")
        print("\033[92mDone\033[0m") 
        return TL
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")
        exit()

# Loads the predictions from a .csv file
def load_predictions(true_labels):
    try:
        # Loads the predictions 
        predictions_path = input("\nPredictions [\033[90m.csv path\033[0m] : ") 
        predictions_df = pd.read_csv(predictions_path)
        # Verifies that the 'KitNET Predictions' column exists in the dataframe
        if 'KitNET Predictions' not in predictions_df.columns:
            print("\033[91mPredictions not found 🔥\033[90mProvide the required information\033[0m")
            exit()
        predictions = np.array(predictions_df['KitNET Predictions'])
        # Loads the flowIDs if required
        if 'FlowIDs' not in predictions_df.columns:
            print("\033[91mFlowIDs not found 🔥\033[90mProvide the required information\033[0m")
            exit()
        flowIDs = np.array(predictions_df['FlowIDs'])
        print(f"\033[90mLoaded {len(predictions)} predictions and {len(flowIDs)} flowIDs for {len(true_labels)} true labels\033[0m\n")
        return predictions, flowIDs
    
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")
        exit()
    
# Builds and runs the original version of Kitsune based on KitNET
def run_kitsune():
    global features
    # PARAMETERS
    current_packet = 0
    predicted_labels = []
    true_labels = load_TL()
    # Loads a .pcap file
    pcap_path = input("\nPackets [\033[90m.pcap path\033[0m] : ")
    try:
        # Runs Kitsune
        print("\n\033[1;97mStarting KitNET 🦊\033[0m")
        kitsune = Kitsune(pcap_path, packet_limit, max_AutoEncoders, FM_grace, AD_grace)
        start = time.time()
        # Processes the packets and visualizes the progress bars
        with Progress(*custom_columns) as progress:
            # Generates a task for each Kitsune phase
            FM_task = progress.add_task("FM Training", total=FM_grace)
            AD_task = progress.add_task("AD Training", total=AD_grace, visible=False)
            # Retrieves the number of packets extracted from the .pcap file
            total_packets = len(kitsune.FE.packets)
            # Computes the total number of packets to be processed in the detection phase [ tot. packets - packets used for the training phases ]
            detection_packets = total_packets - FM_grace - AD_grace
            if detection_packets <= 0:
                print("\033[93mNo packets left to process after training 📣\033[0m\n")  
                return
            DE_task = progress.add_task("Detection", total=detection_packets, visible=False)
  
            while True:
                current_packet += 1
                # Starts the packet analysis
                rmse, flowID = kitsune.process_packet()
                if rmse == -1:
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
        print(f"\033[90mElapsed time : {(stop - start) / 60:.6f} minutes\033[0m")
        print(f"\033[90mKitNET has made {len(predicted_labels)} predictions for {len(true_labels)} true labels\033[0m")
        # Saves the predicted labels in an external .csv file for further processing
        pcap_filename = os.path.basename(pcap_path)
        pcap_name_without_ext = pcap_filename.replace('.pcap', '')
        desktop_path = os.path.expanduser("~/Desktop")
        csv_filename = f"{pcap_name_without_ext}_predictions.csv"
        csv_path = os.path.join(desktop_path, csv_filename)
        print(f"\033[90mSaving predicted labels to {csv_path}\033[0m")  
        pd.DataFrame(predicted_labels, columns=['KitNET Predictions', 'FlowIDs']).to_csv(csv_path, index=False)
        print("\033[92mDone\033[0m\n")
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\033[1m\nSimulator 🤖\033[0m")
    print("\033[90mSelect an option to continue\n\033[0m")
    
    # Menu
    while True:
        print("\033[97m1. KitNET\033[0m")
        print("\033[97m2. Architecture Benchmarks\033[0m")
        print("\033[97m3. KitNET Benchmark\033[0m")
        print("\033[97m4. Merge Metrics\033[0m")
        print("\033[97m5. Quit\033[0m")
        user_choice = input("\n\033[97mInsert your choice [\033[90m1-5\033[97m] : \033[0m")
        
        # Validates the user input
        if user_choice not in ["1", "2", "3", "4", "5"]:
            print("\033[91mInvalid choice 🔥\033[0m\n\033[90mEnter a valid number in the range\n\033[0m")
            continue
        
        # Runs the original version of Kitsune based on KitNET and saves the predicted labels in an external .csv file for further processing
        if user_choice == "1":
            run_kitsune()
            
        # Compares the performance of our experimental architectures [ Sampling and Wasp Detection ]
        elif user_choice == "2":
            # Loads the true labels
            true_labels = load_TL()
            # Loads the predictions generated by KitNET
            predictions, flowIDs = load_predictions(true_labels)
            tools.benchmark(predictions, flowIDs, true_labels)
        
        elif user_choice == "3":
            # Loads the true labels and the predictions 
            true_labels = load_TL()
            predictions, _ = load_predictions(true_labels)
            # Evaluates the performances of the original version of KitNET
            tools.kitBenchmark(predictions, true_labels)
        
        # Merges the metrics from multiple CSV files and generates combined plots
        elif user_choice == "4":
            tools.merge_metrics()
        
        # Quits the program
        elif user_choice == "5":
            exit()
