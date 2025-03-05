# MODULES
import time
import zipfile
import numpy as np
import pandas as pd
import os
from Kitsune import Kitsune
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn

# PARAMETERS
# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(script_dir, "mirai_packets.pcap")
path_labels = os.path.join(script_dir, "mirai_true_labels.csv")
# Limit to the number of packets to process
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
# Labels 
labels_dataframe = pd.read_csv(path_labels, header=None)
true_labels = labels_dataframe.iloc[:, 0].values 
# Predicted labels
predicted_labels = []
# Styles the TimeElapsedColumn from the rich.progress module
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

# Saves the predicted labels in a CSV file for further processing
def save_predictions(predicted_labels, path):
    pcap_filename = os.path.basename(path)
    pcap_name_without_ext = pcap_filename.replace('.pcap', '')
    desktop_path = os.path.expanduser("~/Desktop")
    csv_filename = f"Kitsune_predicted_{pcap_name_without_ext}.csv"
    csv_path = os.path.join(desktop_path, csv_filename)
    # Creates a dataframe with two columns : 'predictions' and 'flowID'
    pd.DataFrame(predicted_labels, columns=['predictions', 'flowID']).to_csv(csv_path, index=False)
    print(f"\033[90mPredicted labels saved to [{csv_path}]\033[0m")

# Builds Kitsune
def run_Kitsune():
    global current_packet, true_labels, predicted_labels
    kitsune = Kitsune(path, packet_limit, max_AutoEncoders, FM_grace, AD_grace)
    print("\033[90mRunning Kitsune\033[0m")
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
                print("\033[93mAfter the training phase there are no packets left to process 📣\033[0m\n")
                return
            DE_task = progress.add_task("Detection", total=detection_packets, visible=False)
        except (AttributeError, TypeError):
            print("\033[91mSomething went wrong with the detection task creation 🔥\033[0m\n")
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
                    # Stores the prediction and the flowID as a tuple
                    predicted_labels.append((1, flowID))
                else:
                    predicted_labels.append((0, flowID))  
                    
    stop = time.time()
    print(f"\033[92mSuccess!\n\033[90mElapsed time: {stop - start:.2f} seconds\033[0m")
    # Sanitizes the label vectors
    true_labels = true_labels[FM_grace + AD_grace:]
    print(f"\033[90mKitsune has predicted {len(predicted_labels)} / {len(true_labels)} labels\033[0m")
    save_predictions(predicted_labels, path)

if __name__ == "__main__":
    print("\n\033[38;5;214mKitsune 🦊\033[0m")
    run_Kitsune()

