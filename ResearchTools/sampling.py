# IMPORTS
import os
import csv
import math
import numpy as np
import matplotlib.pyplot as plot
from pathlib import Path

# Generate a sampling mask 
# It is a BOOLEAN vector where [True] means that the i-th packet has been sampled [ use KitNET prediction ]
# Faster approach rather then using a for-loop because it leverages Numpy's vectorized operations
def probabilistic_sampling (rate, N):
    # Generate a vector of random numbers between 0 and 1 [ length = N ]
    sampling_probabilities = np.random.uniform(0, 1, N)
    # Generate the sampling mask
    # IDEA : suppose a sampling rate of 0.3 out of 1 -> this means that a packet has a 30% chance of being sampled
    # What is the likelihood that a number appears in the interval [0, 0.3] knowing that the numbers are uniformly distributed in the interval [0, 1]? -> 30%
    sampling_mask = sampling_probabilities < rate
    return sampling_mask

# Conduct probabilistic sampling on packets and compute a bunch of metrics
def naive_sampling (predictions, rate, true_labels):
    # Store the pre-processed predictions [ KitNET's predictions ]
    sampled_predictions = predictions.copy()
    # The number of predictions is equal to the number of packets in the original .pcap file
    N = len(predictions)
    # Generate the sampling mask
    sampling_mask = probabilistic_sampling(rate, N)
    # Set the prediction to 0 for all the 'non-sampled' packets
    sampled_predictions[sampling_mask == False] = 0
    
    # CONFUSION MATRIX : classification scoreboard
    # TP [ True Positives ] are the malicious packets predicted as malicious
    # Summing the instances where both sampled_predictions and true_labels are equal to the specified value
    TP = np.sum((sampled_predictions == 1) & (true_labels == 1))
    # FP [ False Positives ] are the benign packets predicted as malicious
    FP = np.sum((sampled_predictions == 1) & (true_labels == 0))
    # FN [ False Negatives ] are the malicious packets predicted as benign
    FN = np.sum((sampled_predictions == 0) & (true_labels == 1))
    # TN [ True Negatives ] are the benign packets predicted as benign
    TN = np.sum((sampled_predictions == 0) & (true_labels == 0))

    # PRECISION 
    # How often the algorithm is right when it claims a packet is malicious 
    # A high precision value means few false alarms
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    # RECALL
    # How many of the actual malicious packets the algorithm catches
    # High recall means fewer misses
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    # F1 SCORE
    # The harmonic mean of precision and recall
    # A single measure that punishes extreme imbalance -> high precision and low recall or vice versa
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    # ACCURACY
    # Overall fraction of correctly classified packets both malicious and benign
    accuracy = (TP + TN) / (TP + TN + FP + FN) if N > 0 else 0
    # Return the computed metrics 
    return accuracy, precision, recall, f1, TP, FP, FN, TN

# Conduct the sampling procedure making assumptions by looking at the registered malicious flows
def wasp_detection (predictions, flowIDs, rate, true_labels):
    # Recorded malicious flows
    wasp_nest = set()
    # Store the pre-processed predictions [ KitNET's predictions ]
    wasp_predictions = predictions.copy()
    # The number of predictions is equal to the number of packets in the original .pcap file
    N = len(predictions)
    # Generate the sampling mask
    sampling_mask = probabilistic_sampling(rate, N)
    # [ Counter ] Packets labeled as malicious with the Wasp Detection sampling procedure 
    detected_wasps = 0
    
    # Process packets sequentially to maintain temporal consistency
    # The wasp_nest is built incrementally as we encounter sampled malicious packets
    for i in range(N):
        # Process sampled packets first
        if sampling_mask[i] == True:
            # For sampled packets keep KitNET's predictions unchanged
            wasp_predictions[i] = predictions[i]
            # If the sampled packet is malicious, add its flowID to the wasp_nest
            if predictions[i] == 1:
                wasp_nest.add(flowIDs[i])
        else:
            # Process non-sampled packets looking at the wasp_nest (built so far)
            # IF the packet's flow belongs to the wasp_nest label the packet as malicious too
            if flowIDs[i] in wasp_nest:
                detected_wasps += 1
                wasp_predictions[i] = 1
            else:
                wasp_predictions[i] = 0
    
    # METRICS
    # Compute and return the metrics 
    TP = np.sum((wasp_predictions == 1) & (true_labels == 1))
    FP = np.sum((wasp_predictions == 1) & (true_labels == 0))
    FN = np.sum((wasp_predictions == 0) & (true_labels == 1))
    TN = np.sum((wasp_predictions == 0) & (true_labels == 0))
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if N > 0 else 0
    return accuracy, precision, recall, f1, detected_wasps, TP, FP, FN, TN

# BENCHMARKS
# Due to the randomic nature of the sampling process each benchmark is run multiple times and then the results are averaged to obtain a more accurate result
def benchmark (predictions, flowIDs, true_labels, rates = None, iterations = 300, destination_folder = None, training_packets = 55000):
    # Benchmarks results
    naive_recall_results = []
    naive_precision_results = []
    naive_f1_score_results = []
    naive_accuracy_results = []
    naive_tp_results = []
    naive_fp_results = []
    naive_fn_results = []
    naive_tn_results = []
    wasps_recall_results = []
    wasps_precision_results = []
    wasps_f1_score_results = []
    wasps_accuracy_results = []
    wasps_tp_results = []
    wasps_fp_results = []
    wasps_fn_results = []
    wasps_tn_results = []
    
    # Default sampling rates 
    if rates is None:
        rates = [0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]

    # Attack
    attack = input("\033[97mAttack : \033[0m").lower()
    # Generate the output .csv filename and save it to the specified folder
    if destination_folder is None:
        destination_folder = str(Path.home() / "Desktop")
    os.makedirs(destination_folder, exist_ok=True)
    # Create plots folder within destination folder
    plots_folder = os.path.join(destination_folder, 'plots')
    os.makedirs(plots_folder, exist_ok=True)
    # Create metrics folder within destination folder
    metrics_folder = os.path.join(destination_folder, 'metrics')
    os.makedirs(metrics_folder, exist_ok=True)
    csv_path = os.path.join(metrics_folder, f"{attack}_metrics.csv")
    csv_data = []

    print("\n\033[1;97mArchitecture Benchmarks 🏛️\033[0m")
    print("\033[90mStarting the benchmarking procedure...\033[0m")
    for rate in rates:
        # PARAMETERS
        # Number of predictions -> number of packets in the .pcap file
        N = len(predictions)
        # Number of sampled packets
        M = math.floor(N * rate)

        print(f"\033[97m\nSampling Rate [\033[90m R \033[37m] is \033[1m{rate / (10 ** int(math.log10(rate))):.2f} × 10^{int(math.log10(rate))}\033[0m\033[90m or {rate:.8f}\033[0m")
        print(f"\033[97mSampling Period [\033[90m 1/R \033[37m] is \033[1m{(1/rate) / (10 ** int(math.log10(1/rate))):.2f} × 10^{int(math.log10(1/rate))}\033[0m\033[90m or {1/rate:.8f}\033[0m")
        print("\033[90m" + "─" * 57 + "\033[0m")
        print(f"\033[97mKitNET [\033[90m P \033[37m] is processing \033[1m{M}\033[0m\033[90m packets\033[0m")
        print(f"\033[97mWasp Detection [\033[90m 1-P \033[37m] is predicting \033[1m{N - M}\033[0m\033[90m packets\033[0m")
        # Averaging accumulators
        total_naive_recall = 0
        total_naive_precision = 0
        total_naive_f1 = 0
        total_naive_accuracy = 0
        total_naive_tp = 0
        total_naive_fp = 0
        total_naive_fn = 0
        total_naive_tn = 0
        total_wasps_recall = 0
        total_wasps_precision = 0
        total_wasps_f1 = 0
        total_wasps_accuracy = 0
        total_wasps_tp = 0
        total_wasps_fp = 0
        total_wasps_fn = 0
        total_wasps_tn = 0
        total_wasps_detected = 0
        
        for _ in range(iterations):
            # Compute the metrics for the architectures
            sampling_accuracy, sampling_precision, sampling_recall, sampling_f1, sampling_tp, sampling_fp, sampling_fn, sampling_tn = naive_sampling(predictions, rate, true_labels)
            wasps_accuracy, wasps_precision, wasps_recall, wasps_f1, wasps_detected, wasps_tp, wasps_fp, wasps_fn, wasps_tn = wasp_detection(predictions, flowIDs, rate,true_labels)
            # Accumulate the results
            total_naive_recall += sampling_recall
            total_naive_precision += sampling_precision
            total_naive_f1 += sampling_f1
            total_naive_accuracy += sampling_accuracy
            total_naive_tp += sampling_tp
            total_naive_fp += sampling_fp
            total_naive_fn += sampling_fn
            total_naive_tn += sampling_tn
            total_wasps_recall += wasps_recall
            total_wasps_precision += wasps_precision
            total_wasps_f1 += wasps_f1
            total_wasps_accuracy += wasps_accuracy
            total_wasps_tp += wasps_tp
            total_wasps_fp += wasps_fp
            total_wasps_fn += wasps_fn
            total_wasps_tn += wasps_tn
            total_wasps_detected += wasps_detected
        
        # Calculate the average values and stores them in the result lists 
        avg_naive_recall = total_naive_recall / iterations
        avg_naive_precision = total_naive_precision / iterations
        avg_naive_f1 = total_naive_f1 / iterations
        avg_naive_accuracy = total_naive_accuracy / iterations
        avg_naive_tp = total_naive_tp / iterations
        avg_naive_fp = total_naive_fp / iterations
        avg_naive_fn = total_naive_fn / iterations
        avg_naive_tn = total_naive_tn / iterations
        avg_wasps_recall = total_wasps_recall / iterations
        avg_wasps_precision = total_wasps_precision / iterations
        avg_wasps_f1 = total_wasps_f1 / iterations
        avg_wasps_accuracy = total_wasps_accuracy / iterations
        avg_wasps_tp = total_wasps_tp / iterations
        avg_wasps_fp = total_wasps_fp / iterations
        avg_wasps_fn = total_wasps_fn / iterations
        avg_wasps_tn = total_wasps_tn / iterations
        avg_wasps_detected = total_wasps_detected / iterations
        print(f"\033[97mMalicious Wasps [\033[90m (1-P)*Q \033[37m] detected : \033[1m{math.floor(avg_wasps_detected)}\033[0m\033[90m\033[0m")
        print(f"\033[97mBenign Wasps [\033[90m (1-P)*(1-Q) \033[37m] detected : \033[1m{N - M - math.floor(avg_wasps_detected)}\033[0m\033[90m\033[0m")
        naive_recall_results.append(avg_naive_recall)
        naive_precision_results.append(avg_naive_precision)
        naive_f1_score_results.append(avg_naive_f1)
        naive_accuracy_results.append(avg_naive_accuracy)
        naive_tp_results.append(avg_naive_tp)
        naive_fp_results.append(avg_naive_fp)
        naive_fn_results.append(avg_naive_fn)
        naive_tn_results.append(avg_naive_tn)
        wasps_recall_results.append(avg_wasps_recall)
        wasps_precision_results.append(avg_wasps_precision)
        wasps_f1_score_results.append(avg_wasps_f1)
        wasps_accuracy_results.append(avg_wasps_accuracy)
        wasps_tp_results.append(avg_wasps_tp)
        wasps_fp_results.append(avg_wasps_fp)
        wasps_fn_results.append(avg_wasps_fn)
        wasps_tn_results.append(avg_wasps_tn)
        
        # Store the data for the .csv
        csv_data.append({
            'rate': rate,
            'naive_recall': avg_naive_recall,
            'naive_precision': avg_naive_precision,
            'naive_f1': avg_naive_f1,
            'naive_accuracy': avg_naive_accuracy,
            'naive_tp': avg_naive_tp,
            'naive_fp': avg_naive_fp,
            'naive_fn': avg_naive_fn,
            'naive_tn': avg_naive_tn,
            'wasps_recall': avg_wasps_recall,
            'wasps_precision': avg_wasps_precision,
            'wasps_f1': avg_wasps_f1,
            'wasps_accuracy': avg_wasps_accuracy,
            'wasps_tp': avg_wasps_tp,
            'wasps_fp': avg_wasps_fp,
            'wasps_fn': avg_wasps_fn,
            'wasps_tn': avg_wasps_tn
        })
        print("\033[90m" + "─" * 57 + "\033[0m")
        print("\033[1;96mMetrics\033[0m\n")
        # Visualize the metrics for the naive sampling approach
        print(f"\033[97mNaive Sampling\033[0m")
        print(f"\033[97mRecall [\033[90m value \033[37m] is \033[1m{avg_naive_recall:.8f}\033[0m")
        print(f"\033[97mPrecision [\033[90m value \033[37m] is \033[1m{avg_naive_precision:.8f}\033[0m")
        print(f"\033[97mF1 Score [\033[90m value \033[37m] is \033[1m{avg_naive_f1:.8f}\033[0m")
        print(f"\033[97mAccuracy [\033[90m value \033[37m] is \033[1m{avg_naive_accuracy:.8f}\033[0m")
        print(f"\033[97mTP are \033[1m{avg_naive_tp/1000:.2f}K\033[0m")
        print(f"\033[97mFP are \033[1m{avg_naive_fp/1000:.2f}K\033[0m")
        print(f"\033[97mFN are \033[1m{avg_naive_fn/1000:.2f}K\033[0m")
        print(f"\033[97mTN are \033[1m{avg_naive_tn/1000:.2f}K\033[0m")
        # Visualize the metrics for the wasp_detection architecture
        print(f"\033[97m\nWasp Detection\033[0m")
        print(f"\033[97mRecall [\033[90m value \033[37m] is \033[1m{avg_wasps_recall:.8f}\033[0m")
        print(f"\033[97mPrecision [\033[90m value \033[37m] is \033[1m{avg_wasps_precision:.8f}\033[0m")
        print(f"\033[97mF1 Score [\033[90m value \033[37m] is \033[1m{avg_wasps_f1:.8f}\033[0m")
        print(f"\033[97mAccuracy [\033[90m value \033[37m] is \033[1m{avg_wasps_accuracy:.8f}\033[0m")
        print(f"\033[97mTP are \033[1m{avg_wasps_tp/1000:.2f}K\033[0m")
        print(f"\033[97mFP are \033[1m{avg_wasps_fp/1000:.2f}K\033[0m")
        print(f"\033[97mFN are \033[1m{avg_wasps_fn/1000:.2f}K\033[0m")
        print(f"\033[97mTN are \033[1m{avg_wasps_tn/1000:.2f}K\033[0m")
    
    # Save the metrics to the .csv file
    with open(csv_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([f"{attack}", f"Training packets: {training_packets}", f"Packets processed: {len(predictions)}"])
        # Insert an empty row
        csv_writer.writerow([])  
        csv_writer.writerow([
            "Sampling Rate", 
            "NS_Recall", "NS_Precision", "NS_F1", "NS_Accuracy",
            "NS_TP", "NS_FP", "NS_FN", "NS_TN",
            "WD_Recall", "WD_Precision", "WD_F1", "WD_Accuracy",
            "WD_TP", "WD_FP", "WD_FN", "WD_TN"
        ])
        for data in csv_data: 
            # Write the data for each rate
            csv_writer.writerow([
                data['rate'],
                f"{data['naive_recall']:.8f}", f"{data['naive_precision']:.8f}", f"{data['naive_f1']:.8f}", f"{data['naive_accuracy']:.8f}",
                f"{data['naive_tp']:.8f}", f"{data['naive_fp']:.8f}", f"{data['naive_fn']:.8f}", f"{data['naive_tn']:.8f}",
                f"{data['wasps_recall']:.8f}", f"{data['wasps_precision']:.8f}", f"{data['wasps_f1']:.8f}", f"{data['wasps_accuracy']:.8f}",
                f"{data['wasps_tp']:.8f}", f"{data['wasps_fp']:.8f}", f"{data['wasps_fn']:.8f}", f"{data['wasps_tn']:.8f}"
            ])
    print(f"\033[90mSaving the collected metrics to {destination_folder}...\033[0m")
    print("\033[1;92mDone\033[0m\n")
    
    # Calculate the inverse of each rate
    inverse_rates = [1/rate for rate in rates]
    
    # PLOTS -> logarithmic scale for the x-axis
    # RECALL plot 
    # Measure the fraction of all malicious packets in the .pcap that have been successfully detected
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_recall_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_recall_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('Recall', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_recall.pdf'))
    
    # PRECISION plot
    # Precision measures the fraction of detected malicious packets that are actually malicious
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_precision_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_precision_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('Precision', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_precision.pdf'))
    
    # F1 SCORE plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_f1_score_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_f1_score_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('F1 Score', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_F1.pdf'))
    
    # ACCURACY plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_accuracy_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_accuracy_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('Accuracy', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_accuracy.pdf'))
    
    # TP [ True Positives ] plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_tp_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_tp_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('True Positives', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_TP.pdf'))
    
    # FP [ False Positives ] plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_fp_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_fp_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('False Positives', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_FP.pdf'))
    
    # FN [ False Negatives ] plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_fn_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_fn_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('False Negatives', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_FN.pdf'))
    
    # TN [ True Negatives ] plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 22})
    plot.plot(inverse_rates, naive_tn_results, marker='o', linestyle=':', linewidth=2, color='#0B84FF', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_tn_results, marker='s', linestyle='-', linewidth=2, color='#FF375F', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10, fontsize=24)
    plot.ylabel('True Negatives', fontweight='semibold', labelpad=10, fontsize=24)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle=':', color='gray')
    plot.legend(framealpha=1, facecolor='white', edgecolor='lightgray', fontsize=14)
    plot.tight_layout()
    plot.savefig(os.path.join(plots_folder, f'{attack.lower()}_TN.pdf'))

