# MODULES
import time
import math
import numpy as np
import pandas as pd
import os
import seaborn as sns
from Kitsune import Kitsune
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn

# PARAMETERS
# Gets the folder where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(script_dir, "mirai_packets.pcap")
path_labels = os.path.join(script_dir, "mirai_true_labels.csv")
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
# Labels
labels_dataframe = pd.read_csv(path_labels, header=None)
true_labels = labels_dataframe.iloc[:, 0].values 
# Sanitizes the label vectors
true_labels = true_labels[FM_grace + AD_grace:]
# Sampling labels 
predicted_labels = []
sampled_predictions = []
wasp_labels = []

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

# Performs a probabilistic sampling of the packets 
def naive_sampling (predictions, rate, true_labels):
    global sampled_predictions
    print(f"true_labels: {len(true_labels)}")
    # Resets the sampled predictions
    sampled_predictions = []
    # Processed predictions [ initializes with the original predictions that will be modified later ] 
    sampled_predictions = predictions.copy()
    # Sampling parameters
    N = len(predictions)
    M = math.floor(N * rate)
    print(f"\n\033[90mSampling with a rate of {rate:.2f} -→ {M}/{N} packets\033[0m")
    print(f"\033[90mThere are {N} packets in total and {M} samples to collect \033[0m")    # Retrieves M random indices [ the indices of the packets to be sampled and left unchanged ]
    indices = np.random.choice(N, size=M, replace=False)
    # Sets all values to 0 except those at selected indices [ 0 means that the packet is not malicious ]
    sampling_mask = np.ones(N, dtype=bool)
    sampling_mask[indices] = False
    sampled_predictions[sampling_mask] = 0
    # Calculates the difference between original and sampled predictions
    different_count = np.sum(predictions != sampled_predictions)
    difference_percentage = (different_count / N) * 100
    # Prints some useful information about the sampling procedure
    print(f"\033[97mPackets sampled\033[90m [ unchanged predictions ] \033[97m: {M} -→ {(M/N)*100:.2f}%\033[0m")
    print(f"\033[97mPackets modified\033[90m [ malicious packets become benign ] \033[97m: {different_count} -→ {difference_percentage:.2f}%\033[0m")
    # Computes the precision and recall metrics of the sampling procedure
    if len(true_labels) != len(sampled_predictions):
        print(f"\033[91mThere is a mismatch between the number of true labels and the number of sampled predictions 🔥\033[0m\n\033[90mLook at the provided files for possible errors\033[0m")
        return
    # Computes the metrics 
    true_positives = np.sum((sampled_predictions == 1) & (true_labels == 1))
    false_positives = np.sum((sampled_predictions == 1) & (true_labels == 0))
    false_negatives = np.sum((sampled_predictions == 0) & (true_labels == 1))
    true_negatives = np.sum((sampled_predictions == 0) & (true_labels == 0))
    # Computes the precision [ TP / (TP + FP) ] 
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    # Computes the recall [ TP / (TP + FN) ]
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    # Computes the F1 score [ 2 * (precision * recall) / (precision + recall) ] 
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    # Computes the accuracy [ (TP + TN) / (TP + TN + FP + FN) ]
    accuracy = (true_positives + true_negatives) / (true_positives + true_negatives + false_positives + false_negatives) if N > 0 else 0
    # Prints the metrics
    print(f"\033[97mPrecision = {precision:.4f}\033[0m")
    print(f"\033[97mRecall = {recall:.4f}\033[0m")
    print(f"\033[97mF1 Score = {f1:.4f}\033[0m")
    print(f"\033[97mAccuracy = {accuracy:.4f}\033[0m")
    print(f"\033[92mDone!\033[0m\n")
    return accuracy, precision, recall, f1

# Performs a sampling procedure that take into account the observed malicious flows
def wasps_detection (predictions, true_labels, rate = 1):
    global sampled_predictions
    print("\n\033[90mRunning wasps detection\033[0m")
    print(f"\033[92mDone!\n")
    return 

# Computes some metrics to evaluate the performance of the detection system
def performance_analysis (predictions, true_labels, rate):
    sampling_accuracy, sampling_precision, sampling_recall, sampling_f1 = naive_sampling(predictions, rate, true_labels)
    return

# Builds Kitsune
def run_kitsune():
    global current_packet, true_labels, predicted_labels
    kitsune = Kitsune(path, packet_limit, max_AutoEncoders, FM_grace, AD_grace)
    print("\n\033[90mRunning Kitsune\033[0m")
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
    print(f"\033[92mDone!\n\033[90mElapsed time: {stop - start:.2f} seconds\033[0m")
    print(f"\033[90mKitsune has predicted {len(predicted_labels)} / {len(true_labels)} labels\033[0m\n")
    save_predictions(predicted_labels, path)

if __name__ == "__main__":
    print("\n\033[38;5;214mKitsune 🦊\033[0m")
    print("\033[90mSelect an option to continue\n\033[0m")
    # Menu
    while True:
        print("\033[97m1. Kitsune\033[0m")
        print("\033[97m2. Sampling\033[0m")
        print("\033[97m3. Wasps detection\033[0m")
        print("\033[97m4. Performance analysis\033[0m")
        print("\033[97m5. Quit\033[0m")
        user_choice = input("\n\033[97mInsert your choice \033[90m[ 1-5 ]\033[97m : \033[0m")
        
        # Validates user input
        if user_choice not in ["1", "2", "3", "4", "5"]:
            print("\033[91mInvalid choice 🔥\033[0m\n\033[90mPlease enter a number in the range\n\033[0m")
            continue
            
        if user_choice == "1":
            # Runs Kitsune and saves the predicted labels in a CSV file
            run_kitsune()
            
        elif user_choice == "2":
            # Retrieves the CSV file containing the predicted labels
            default_path = os.path.expanduser("~/Desktop/Kitsune_predicted_mirai_packets.csv")
            csv_path = input(f"\033[97mEnter predictions CSV \033[90m[ default at {default_path} ]\033[97m : \033[0m")
            # Uses the default path if user didn't provide one [ user pressed ENTER ]
            if not csv_path.strip():
                csv_path = default_path
            # Verifies that the files exist and that are valid CSVs
            if not os.path.exists(csv_path):
                print("\033[91mThe provided file does not exist 🔥\033[0m\n\033[90mProvide a valid file\n\033[0m")
                continue
            try:
                # Loads the predictions and the true labels from the CSV files
                predictions_df = pd.read_csv(csv_path)
                # Checks if 'predictions' column exists
                if 'predictions' not in predictions_df.columns:
                    print("\033[91mThe provided CSV file does not contain valid predictions 🔥\033[90mProvide the required information\033[0m")
                    continue
                predictions = np.array(predictions_df['predictions'])
                print(f"\033[90mLoaded {len(predictions)} predictions and {len(true_labels)} true labels\033[0m")
                # Sampling rate validation
                rate = 1.0  
                while True:
                    user_rate = input("\033[97mEnter sampling rate \033[90m[ default is 1.0 ]\033[97m : \033[0m")
                    if not user_rate.strip():
                        break
                    try:
                        rate_value = float(user_rate)
                        if 0.0 <= rate_value <= 1.0:
                            rate = rate_value
                            break
                        else:
                            print("\033[91mInvalid rate 🔥\033[0m\n\033[90mSampling rate must be between 0 and 1\033[0m")
                    except ValueError:
                        print("\033[91mInvalid rate format 🔥\033[0m\n\033[90mPlease enter a valid number\033[0m")
                
                # Performs the sampling with the provided rate
                naive_sampling(predictions, rate, true_labels)
            # Exceptions handling
            except pd.errors.EmptyDataError:
                print("\033[91mThe CSV file is empty 🔥\033[0m\n")
                continue
            except pd.errors.ParserError:
                print("\033[91mThe file is not a valid CSV 🔥\033[0m\n")
                continue
            except Exception as e:
                print(f"\033[91mGeneric Error 🔥\033[0m\n\033[90m{str(e)}\033[0m\n")
                continue
            
        elif user_choice == "3":
            # Simulates a wasps detection [ malicious flows detections ] over the predicted labels
            wasps_detection(predicted_labels, true_labels)
        elif user_choice == "4":
            # Computes some metrics to evaluate the performance of the detection system
            performance_analysis(predicted_labels, true_labels)
        elif user_choice == "5":
            # Quits the program
            print("\033[90mGoodbye Friend 🤖\033[0m")
            break
