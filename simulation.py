# MODULES
import os
import time
import numpy as np
import pandas as pd
from Kitsune.Kitsune import Kitsune
from ResearchTools import sampling
from rich.progress import Progress, TimeElapsedColumn, BarColumn, TextColumn
from ANN.KitNET import KitNET
from Kitsune.FeatureExtractor import *

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
    TL_path = input("\nTrue labels [\033[90m .csv path \033[0m] : ")
    print("\033[90mLoading the true labels...\033[0m")
    try:
        # Loads the true labels from the first column of the .csv file
        dataframe = pd.read_csv(TL_path, header=0)
        TL = np.array(dataframe.iloc[:, 0])

        # QUESTION : ask the user if the first [ FM_grace + AD_grace ] rows of the true labels should be skipped
        skip_grace = input("Does the .csv file include labels for the packets used in training? [\033[90m y • n \033[0m] : ").strip().lower()
        if skip_grace == 'y' or skip_grace == 'yes':
            # Removes the training packets labels
            TL = TL[(FM_grace + AD_grace):]
            print(f"\033[90mSkipping the first {FM_grace + AD_grace} rows...\033[0m")
        print(f"\033[90mLoaded {len(TL)} true labels\033[0m")
        print("\033[1;92mDone\033[0m")
        return TL, TL_path
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        exit()

# Loads the predictions from a .csv file
def load_predictions(true_labels):
    try:
        # Loads the predictions 
        predictions_path = input("\nPredictions [\033[90m .csv path \033[0m] : ") 
        predictions_df = pd.read_csv(predictions_path)
        # Verifies that the 'KitNET Predictions' column exists in the dataframe
        if 'KitNET Predictions' not in predictions_df.columns:
            print(f"\033[1;91mError 🔥\n\033[0;90mPredictions not found. Provide the required information\n\033[0m")
            exit()
        predictions = np.array(predictions_df['KitNET Predictions'])
        # Loads the flowIDs if required
        if 'FlowIDs' not in predictions_df.columns:
            print(f"\033[1;91mError 🔥\n\033[0;90mFlowIDs not found! Provide the required information\n\033[0m")
            exit()
        flowIDs = np.array(predictions_df['FlowIDs'])
        print("\033[90mLoading predictions...\033[0m")
        print(f"\033[90mLoaded {len(predictions)} predictions\033[0m")
        print("\033[1;92mDone\033[0m\n")
        if len(predictions) != len(true_labels):
            print(f"\033[1;93mWarning ⚠️\n\033[0;90mThe number of predictions does not match the number of true labels\n\033[0m")
        return predictions, flowIDs
    
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        exit()
    
# Builds and runs the original version of Kitsune based on KitNET
def run_kitsune():
    global features
    # PARAMETERS
    current_packet = 0
    predicted_labels = []
    true_labels, tl_path = load_TL()
    # Loads a .pcap file
    pcap_path = input("\nPackets [\033[90m .pcap path \033[0m] : ")
    try:
        # Runs Kitsune
        print("\n\033[1;97mKitNET 🦊\033[0m")
        extractor = FE(pcap_path, packet_limit)
        kitnet = KitNET(extractor.get_num_features(), max_AutoEncoders, FM_grace, AD_grace, 0.1, 0.75)
        kitsune = Kitsune(extractor, kitnet)
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
        # Save to the same directory as the true labels file
        tl_directory = os.path.dirname(tl_path)
        csv_filename = f"{pcap_name_without_ext}_predictions.csv"
        csv_path = os.path.join(tl_directory, csv_filename)
        print(f"\033[90mSaving predicted labels to {csv_path}\033[0m")
        pd.DataFrame(predicted_labels, columns=['KitNET Predictions', 'FlowIDs']).to_csv(csv_path, index=False)
        print("\033[1;92mDone\033[0m\n")

    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# Builds and runs Kitsune with split .pcap execution (training on one file, detection on another)
def run_split_kitsune():
    global features
    # PARAMETERS
    current_packet = 0
    predicted_labels = []
    true_labels, tl_path = load_TL()

    # Load training .pcap file
    training_pcap_path = input("Training packets [ \033[90m.pcap path\033[0m ] : ")
    # Load detection .pcap file
    detection_pcap_path = input("Detection packets [ \033[90m.pcap path\033[0m ] : ")

    try:
        # PHASE 1: Training on first .pcap file
        print("\033[1;37m\nTraining phase 🧠\033[0m")
        training_extractor = FE(training_pcap_path, packet_limit)
        training_features = training_extractor.get_num_features()
        print(f"\033[90mComputing {training_extractor.get_num_features()} features per packet...\033[0m")
        kitnet = KitNET(training_features, max_AutoEncoders, FM_grace, AD_grace, 0.1, 0.75)
        training_kitsune = Kitsune(training_extractor, kitnet)

        start = time.time()

        # Train on the training .pcap file
        with Progress(*custom_columns) as progress:
            FM_task = progress.add_task("FM Training", total=FM_grace)
            AD_task = progress.add_task("AD Training", total=AD_grace, visible=False)

            training_packets = len(training_kitsune.FE.packets)
            if training_packets < FM_grace + AD_grace:
                print(f"\033[93mTraining .pcap has {training_packets} packets, but needs at least {FM_grace + AD_grace} for training 📣\033[0m\n")
                return

            while True:
                current_packet += 1
                rmse, flowID = training_kitsune.process_packet()
                if rmse == -1:
                    break

                if current_packet <= FM_grace:
                    progress.update(FM_task, completed=current_packet)
                    if current_packet == FM_grace:
                        progress.update(AD_task, visible=True)
                elif current_packet <= FM_grace + AD_grace:
                    progress.update(AD_task, completed=current_packet - FM_grace)
                else:
                    # Training complete
                    break

        print("\033[1;92mDone\033[0m")
        print("\033[90mTraining phase completed\033[0m\n")

        # PHASE 2: Detection on second .pcap file
        print("\033[1;37mDetection phase 🔦\033[0m")
        detection_extractor = FE(detection_pcap_path, packet_limit)
        detection_features = detection_extractor.get_num_features()
        # Detect a mismatch in the number of features between the training and detection phases
        if detection_features != training_features:
            print(f"\033[91mError 🔥\n\033[0;90mThe number of features in the training and detection .pcap files do not match\n\033[0m")
            return
        # Use the trained KitNET with new extractor
        detection_kitsune = Kitsune(detection_extractor, kitnet)

        current_packet = 0
        predicted_labels = []

        detection_packets = len(detection_kitsune.FE.packets)
        if detection_packets <= 0:
            print("\033[93mThere are no packets in the detection .pcap file 📣\033[0m\n")
            return

        with Progress(*custom_columns) as progress:
            DE_task = progress.add_task("Detection", total=detection_packets)

            while True:
                current_packet += 1
                rmse, flowID = detection_kitsune.process_packet()
                if rmse == -1:
                    break

                progress.update(DE_task, completed=current_packet)

                # Make predictions on all packets in detection phase
                if rmse >= detection_kitsune.AnomDetector.threshold:
                    # Malicious
                    predicted_labels.append((1, flowID))
                else:
                    # Benign
                    predicted_labels.append((0, flowID))

        stop = time.time()
        print(f"\033[90mElapsed time : {(stop - start) / 60:.6f} min\033[0m")

        # Save predictions
        detection_pcap_filename = os.path.basename(detection_pcap_path)
        detection_pcap_name_without_ext = detection_pcap_filename.replace('.pcap', '').replace('.pcapng', '')
        tl_directory = os.path.dirname(tl_path)
        csv_filename = f"{detection_pcap_name_without_ext}_split_predictions.csv"
        csv_path = os.path.join(tl_directory, csv_filename)
        print(f"\033[90mSaving the predicted labels to {csv_path}...\033[0m")
        pd.DataFrame(predicted_labels, columns=['KitNET Predictions', 'FlowIDs']).to_csv(csv_path, index=False)
        print("\033[1;92mDone\033[0m")
        print(f"\033[90mKitNET has made {len(predicted_labels)} predictions\033[0m\n")

    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\033[1m\nSimulator 🤖\033[0m")
    print("\033[90mSelect an option to continue\n\033[0m")
    
    # Menu
    while True:
        print("\033[97m1. Run KitNET [ \033[90mSingle .pcap file\033[97m ]\033[0m")
        print("\033[97m2. Run KitNET [ \033[90mSplit .pcap execution\033[97m ]\033[0m")
        print("\033[97m3. Architecture Benchmarks\033[0m")
        print("\033[97m4. Quit\033[0m")
        user_choice = input("\n\033[97mInsert your choice [ \033[90m1 • 4\033[97m ] : \033[0m")

        # Validates the user input
        if user_choice not in ["1", "2", "3", "4"]:
            print(f"\033[1;91mError 🔥\n\033[0;90mInvalid choice. Enter a valid number in the range\n\033[0m")
            continue
        
        # Runs the original version of Kitsune based on KitNET and saves the predicted labels in an external .csv file for further processing
        if user_choice == "1":
            run_kitsune()
            
        # Runs KitNET with split .pcap execution (train on one file, detect on another)
        elif user_choice == "2":
            run_split_kitsune()

        # Compares the performance of our experimental architectures [ Sampling and Wasp Detection ]
        elif user_choice == "3":
            # Loads the true labels
            true_labels, tl_path = load_TL()
            # Loads the predictions generated by KitNET
            predictions, flowIDs = load_predictions(true_labels)
            # Use the same directory as the true labels file for benchmark output
            destination_folder = os.path.dirname(tl_path)
            sampling.benchmark(predictions, flowIDs, true_labels, destination_folder=destination_folder, training_packets=FM_grace + AD_grace)

        # Quits the program
        elif user_choice == "4":
            print("\033[90mQuitting...\n\033[0m")
            exit()
