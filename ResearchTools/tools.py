import os
import csv
import math
import numpy as np
from numpy.random import default_rng
import matplotlib.pyplot as plot
from pathlib import Path
from sklearn.metrics import roc_curve, roc_auc_score
from scipy.optimize import brentq
from scipy.interpolate import interp1d

# Conducts probabilistic sampling on packets and computes the metrics
def naive_sampling (predictions, rate, true_labels):
    # Stores processed predictions [ initialized from the original for later modification ]
    sampled_predictions = predictions.copy()
    # Sampling parameters and indices
    N = len(predictions)
    M = math.floor(N * rate)
    # Improves the randomness of the probabilistic sampling process
    rng = default_rng()
    indices = rng.choice(N, size=M, replace=False)
    # Sets all values to 0 except at selected indices [ 0 means that the packet is benign ]
    sampling_mask = np.ones(N, dtype=bool)
    sampling_mask[indices] = False
    sampled_predictions[sampling_mask] = 0
    # METRICS
    # TP [ true positives ] : sums the instances where both sampled_predictions and true_labels are equal to 1
    TP = np.sum((sampled_predictions == 1) & (true_labels == 1))
    # FP [ false positives ] : sums the instances where sampled_predictions is equal to 1 and true_labels is equal to 0
    FP = np.sum((sampled_predictions == 1) & (true_labels == 0))
    # FN [ false negatives ] : sums the instances where sampled_predictions is equal to 0 and true_labels is equal to 1
    FN = np.sum((sampled_predictions == 0) & (true_labels == 1))
    # TN [ true negatives ] : sums the instances where both sampled_predictions and true_labels are equal to 0
    TN = np.sum((sampled_predictions == 0) & (true_labels == 0))
    # Computes the precision [ amount of positive predictions that are true positive ] 
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    # Computes the recall [ amount of true positives predicted correctly predicted by the model ]
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    # Computes the F1 score [ harmonic mean of precision and recall ] 
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    # Computes the accuracy [ overall correctness of a model ]
    accuracy = (TP + TN) / (TP + TN + FP + FN) if N > 0 else 0
    # Returns the metrics 
    return accuracy, precision, recall, f1, TP, FP, FN, TN

# Conducts sampling making assumptions looking at the registered malicious flows
def wasp_detection (predictions, flowIDs, rate, true_labels):
    # Set of observed malicious flows
    wasp_nest = set()
    # Stores processed predictions [ initialized from the original for later modification ]
    wasp_predictions = predictions.copy()
    # Sampling parameters and indices
    N = len(predictions)
    M = math.floor(N * rate)
    # Packets labeled as malicious with the Wasp Detection architecture
    detected_wasps = 0
    # Improves the randomness of the probabilistic sampling process
    rng = default_rng()
    indices = rng.choice(N, size=M, replace=False)
    
    # Scans sampled packets to populate the wasp_nest 
    # The wasp_nest is filled with information [ flowIDs ] from the malicious packets that have been sampled 
    for i in indices:
        if predictions[i] == 1:
            wasp_nest.add(flowIDs[i])
    
    # Generates a sampling mask for the indices to be processed
    sampling_mask = np.ones(N, dtype=bool)
    sampling_mask[indices] = False
    
    # Processes each prediction using the sampling mask and wasp_nest logic
    for i in range(N):
        # Processes non-sampled packets using wasp_nest information
        if sampling_mask[i]:
            # If the packet's flow is in wasp_nest, mark it as malicious
            if flowIDs[i] in wasp_nest:
                detected_wasps += 1
                wasp_predictions[i] = 1
            else:
                wasp_predictions[i] = 0
            continue
            
        # For sampled packets keep the original predictions made by KitNET unchanged
        # Removes the counting of detected wasps for sampled packets
        wasp_predictions[i] = predictions[i]
    
    # Calculates the metrics 
    TP = np.sum((wasp_predictions == 1) & (true_labels == 1))
    FP = np.sum((wasp_predictions == 1) & (true_labels == 0))
    FN = np.sum((wasp_predictions == 0) & (true_labels == 1))
    TN = np.sum((wasp_predictions == 0) & (true_labels == 0))
    # Computes the precision 
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    # Computes the recall 
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    # Computes the F1 score 
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    # Computes the accuracy
    accuracy = (TP + TN) / (TP + TN + FP + FN) if N > 0 else 0
    # Returns the metrics 
    return accuracy, precision, recall, f1, detected_wasps, TP, FP, FN, TN

# Computes metrics to evaluate the detection architectures' performance
# Since the sampling is randomic each benchmark is run multiple times and then averaged to obtain a more uniform result
def benchmark (predictions, flowIDs, true_labels, rates = None, iterations = 300):
    # Results of the benchmarks
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
    
    # Sets default rates if none are provided
    if rates is None:
        rates = [0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]

    # Asks the user for the attack name that will be used to name the .csv file for the metrics
    attack = input("\033[97mAttack : \033[0m")
    # Generates the .csv filename and saves it to the desktop
    desktop = str(Path.home() / "Desktop")
    csv_path = os.path.join(desktop, f"{attack}_metrics.csv")
    # Prepares data for CSV
    csv_data = []

    print("\n\033[1;97mArchitecture Benchmarks 🏛️\033[0m\n")
    for rate in rates:
        # Sampling parameters and indices
        N = len(predictions)
        M = math.floor(N * rate)
        
        print(f"\033[97m[\033[90mR\033[97m] Sampling Rate {rate:.8f}\033[0m")
        print(f"\033[97m[\033[90m1/R\033[97m] Sampling Period {1/rate:.8f}\033[0m")
        print("\033[90m" + "─" * 37 + "\033[0m")
        print(f"\033[97m[\033[90mP\033[97m]\033[90m KitNET : {M}\n\033[97m[\033[90m1-P\033[97m]\033[90m Wasp Detection : {N - M}\033[0m")
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
            # Computes the metrics for the architectures
            sampling_accuracy, sampling_precision, sampling_recall, sampling_f1, sampling_tp, sampling_fp, sampling_fn, sampling_tn = naive_sampling(predictions, rate, true_labels)
            wasps_accuracy, wasps_precision, wasps_recall, wasps_f1, wasps_detected, wasps_tp, wasps_fp, wasps_fn, wasps_tn = wasp_detection(predictions, flowIDs, rate,true_labels)
            # Accumulates the results
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
        
        # Calculates the average values and stores them in the result lists 
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
        print(f"\033[97m[\033[90m(1-P)*Q\033[97m]\033[90m Malicious Wasps : {math.floor(avg_wasps_detected)}\n\033[97m[\033[90m(1-P)*(1-Q)\033[97m]\033[90m Benign Wasps : {N - M - math.floor(avg_wasps_detected)}\033[0m")

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
        
        # Stores data for the .csv
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
        print("\033[90m" + "─" * 37 + "\033[0m")
        # Visualizes the metrics for the naive sampling approach
        print(f"\033[97m• Naive Sampling\033[0m")
        print(f"\033[97m[\033[90mRecall\033[97m] :\033[0m {avg_naive_recall:.8f}\n\033[97m[\033[90mPrecision\033[97m] :\033[0m {avg_naive_precision:.8f}\n\033[97m[\033[90mF1 Score\033[97m] :\033[0m {avg_naive_f1:.8f}\n\033[97m[\033[90mAccuracy\033[97m] :\033[0m {avg_naive_accuracy:.8f}")
        print(f"\033[97m[\033[90mTP\033[97m] :\033[0m {avg_naive_tp:.8f}\n\033[97m[\033[90mFP\033[97m] :\033[0m {avg_naive_fp:.8f}\n\033[97m[\033[90mFN\033[97m] :\033[0m {avg_naive_fn:.8f}\n\033[97m[\033[90mTN\033[97m] :\033[0m {avg_naive_tn:.8f}")
        # Visualizes the metrics for the wasp detection architecture
        print(f"\033[97m• Wasp Detection\033[0m")
        print(f"\033[97m[\033[90mRecall\033[97m] :\033[0m {avg_wasps_recall:.8f}\n\033[97m[\033[90mPrecision\033[97m] :\033[0m {avg_wasps_precision:.8f}\n\033[97m[\033[90mF1 Score\033[97m] :\033[0m {avg_wasps_f1:.8f}\n\033[97m[\033[90mAccuracy\033[97m] :\033[0m {avg_wasps_accuracy:.8f}")
        print(f"\033[97m[\033[90mTP\033[97m] :\033[0m {avg_wasps_tp:.8f}\n\033[97m[\033[90mFP\033[97m] :\033[0m {avg_wasps_fp:.8f}\n\033[97m[\033[90mFN\033[97m] :\033[0m {avg_wasps_fn:.8f}\n\033[97m[\033[90mTN\033[97m] :\033[0m {avg_wasps_tn:.8f}")
        print("\033[96mMetrics Collected\033[0m\n")
    
    # Saves the metrics to .csv file
    with open(csv_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([f"Attack: {attack}"])
        csv_writer.writerow([])  # Empty row
        csv_writer.writerow([
            "Sampling Rate", 
            "NS_Recall", "NS_Precision", "NS_F1", "NS_Accuracy",
            "NS_TP", "NS_FP", "NS_FN", "NS_TN",
            "WD_Recall", "WD_Precision", "WD_F1", "WD_Accuracy",
            "WD_TP", "WD_FP", "WD_FN", "WD_TN"
        ])
        for data in csv_data:
            # Write data for each rate
            csv_writer.writerow([
                data['rate'],
                f"{data['naive_recall']:.8f}", f"{data['naive_precision']:.8f}", f"{data['naive_f1']:.8f}", f"{data['naive_accuracy']:.8f}",
                f"{data['naive_tp']:.8f}", f"{data['naive_fp']:.8f}", f"{data['naive_fn']:.8f}", f"{data['naive_tn']:.8f}",
                f"{data['wasps_recall']:.8f}", f"{data['wasps_precision']:.8f}", f"{data['wasps_f1']:.8f}", f"{data['wasps_accuracy']:.8f}",
                f"{data['wasps_tp']:.8f}", f"{data['wasps_fp']:.8f}", f"{data['wasps_fn']:.8f}", f"{data['wasps_tn']:.8f}"
            ])
    print(f"\033[90mSaving the collected metrics to the desktop\033[0m")
    print("\033[92mDone\033[0m\n")
    
    # Calculates the inverse of each rate
    inverse_rates = [1/rate for rate in rates]
    
    # PLOTS [ using logarithmic scale for the x-axis ] 
    # Recall plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_recall_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_recall_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('Recall', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_recall.png'), dpi=384)
    
    # Precision plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_precision_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_precision_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('Precision', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_precision.png'), dpi=384)
    
    # F1 score plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_f1_score_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_f1_score_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('F1 Score', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_F1.png'), dpi=384)
    
    # Accuracy plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_accuracy_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_accuracy_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('Accuracy', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.ylim(-0.05, 1.05)
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_accuracy.png'), dpi=384)
    
    # TP plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_tp_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_tp_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('True Positives', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_tp.png'), dpi=384)
    
    # FP plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_fp_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_fp_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('False Positives', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_fp.png'), dpi=384)
    
    # FN plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_fn_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_fn_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('False Negatives', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_fn.png'), dpi=384)
    
    # TN plot
    plot.figure(figsize=(10, 6))
    plot.rcParams.update({'font.size': 15})
    plot.plot(inverse_rates, naive_tn_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_tn_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='semibold', labelpad=10)
    plot.ylabel('True Negatives', fontweight='semibold', labelpad=10)
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.savefig(os.path.join(desktop, f'{attack.lower()}_tn.png'), dpi=384)

# Computes metrics to evaluate the performance of the original version of KitNET [ implemented following the paper by Mirsky et al. ]
def kitBenchmark(predictions, true_labels):
    print("\033[1;97mKitNET Benchmark 🌱\033[0m")
    print(f"\033[90mThis version of KitNET has m={10} and features={100}\033[0m\n")
    # Computes the basic metrics
    TP = np.sum((predictions == 1) & (true_labels == 1))
    FP = np.sum((predictions == 1) & (true_labels == 0))
    TN = np.sum((predictions == 0) & (true_labels == 0))
    FN = np.sum((predictions == 0) & (true_labels == 1))
    
    # Computes the metrics derived from the ROC curve
    fpr, tpr, thresholds = roc_curve(true_labels, predictions)
    auc = roc_auc_score(true_labels, predictions)
    tpr_at_fpr0 = tpr[np.argmin(np.abs(fpr - 0))]
    tpr_at_fpr001 = tpr[np.argmin(np.abs(fpr - 0.001))]
    fnr_at_fpr0 = 1 - tpr_at_fpr0
    fnr_at_fpr001 = 1 - tpr_at_fpr001
    eer = brentq(lambda x: 1 - x - interp1d(fpr, tpr)(x), 0, 1)
    
    # Visualizes the results
    print(f"\033[97m[\033[90mTP\033[97m] True Positives : \033[0m {TP}")
    print(f"\033[97m[\033[90mFP\033[97m] False Positives : \033[0m {FP}")
    print(f"\033[97m[\033[90mTN\033[97m] True Negatives : \033[0m {TN}")
    print(f"\033[97m[\033[90mFN\033[97m] False Negatives : \033[0m {FN}")
    print("\033[90m" + "─" * 36 + "\033[0m")
    print(f"\033[97m[\033[90mAUC\033[97m] Area Under Curve : \033[0m {auc:.8f}")
    print(f"\033[97m[\033[90mEER\033[97m] Equal Error Rate : \033[0m {eer:.8f}")
    print("\033[90m" + "─" * 36 + "\033[0m")
    print(f"\033[97m[\033[90mTPR -→ FPR = 0\033[97m]     True Positive Rate : \033[0m {tpr_at_fpr0:.8f}")
    print(f"\033[97m[\033[90mTPR -→ FPR = 0.001\033[97m] True Positive Rate : \033[0m {tpr_at_fpr001:.8f}")
    print(f"\033[97m[\033[90mFNR -→ FPR = 0\033[97m]     False Negative Rate : \033[0m {fnr_at_fpr0:.8f}")
    print(f"\033[97m[\033[90mFNR -→ FPR = 0.001\033[97m] False Negative Rate : \033[0m {fnr_at_fpr001:.8f}")
    print("\033[92mDone\033[0m\n")
