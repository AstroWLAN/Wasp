import math
import numpy as np
import matplotlib.pyplot as plot

# Conducts probabilistic sampling on packets
def naive_sampling (predictions, rate, true_labels):
    # Stores processed predictions [ initialized from the original for later modification ]
    sampled_predictions = predictions.copy()
    # Sampling parameters and indices
    N = len(predictions)
    M = math.floor(N * rate)
    indices = np.random.choice(N, size=M, replace=False)
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
    return accuracy, precision, recall, f1

# Samples packets considering observed malicious flows
def wasps_detection (predictions, flowIDs, rate, true_labels):
    # Set of observed malicious flows
    wasp_nest = set()
    # Stores processed predictions [ initialized from the original for later modification ]
    wasp_predictions = predictions.copy()
    # Sampling parameters and indices
    N = len(predictions)
    M = math.floor(N * rate)
    indices = np.random.choice(N, size=M, replace=False)
    
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
        # Left unchanged
        if not sampling_mask[i]:
            continue
        # Reads the original prediction and the flowID of the current packet
        value = predictions[i]
        flow_id = flowIDs[i]
        # CASES
        # Malicious packet with a flowID observed and registered in the wasp_nest
        if value == 1 and flow_id in wasp_nest:
            wasp_predictions[i] = 1
        # Malicious packet with a flowID not observed or registered in the wasp_nest
        elif value == 1 and flow_id not in wasp_nest:
            wasp_predictions[i] = 0
        # Benign packet with a flowID present in the wasp_nest
        elif value == 0 and flow_id in wasp_nest:
            wasp_predictions[i] = 1
        else:
            # Leaves it unchanged
            wasp_predictions[i] = 0
    
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
    return accuracy, precision, recall, f1

# Computes metrics to evaluate the detection architectures' performance
# Since the sampling is randomic each metric is computed multiple times and then averaged to obtain a more uniform result
def benchmark (predictions, flowIDs, true_labels, rates = None, iterations = 10):
    # Results of the tests
    naive_recall_results = []
    naive_precision_results = []
    naive_f1_score_results = []
    wasps_recall_results = []
    wasps_precision_results = []
    wasps_f1_score_results = []
    
    # Sets default rates if none are provided
    if rates is None:
        rates = [0.00001, 0.0001, 0.001, 0.01, 0.1, 0.25, 0.5, 1]
        
    print("\033[97mCollecting the performance of the architectures ⏱️\033[0m\n")
    for rate in rates:
        # Averaging accumulators
        total_naive_recall = 0
        total_naive_precision = 0
        total_naive_f1 = 0
        total_wasps_recall = 0
        total_wasps_precision = 0
        total_wasps_f1 = 0
        
        for _ in range(iterations):
            # Computes the metrics for the architectures
            sampling_accuracy, sampling_precision, sampling_recall, sampling_f1 = naive_sampling(predictions, rate, true_labels)
            wasps_accuracy, wasps_precision, wasps_recall, wasps_f1 = wasps_detection(predictions, flowIDs, rate,true_labels)
            # Accumulates the results
            total_naive_recall += sampling_recall
            total_naive_precision += sampling_precision
            total_naive_f1 += sampling_f1
            total_wasps_recall += wasps_recall
            total_wasps_precision += wasps_precision
            total_wasps_f1 += wasps_f1
        
        # Calculates the average values and stores them in the result lists 
        avg_naive_recall = total_naive_recall / iterations
        avg_naive_precision = total_naive_precision / iterations
        avg_naive_f1 = total_naive_f1 / iterations
        avg_wasps_recall = total_wasps_recall / iterations
        avg_wasps_precision = total_wasps_precision / iterations
        avg_wasps_f1 = total_wasps_f1 / iterations

        naive_recall_results.append(avg_naive_recall)
        naive_precision_results.append(avg_naive_precision)
        naive_f1_score_results.append(avg_naive_f1)
        wasps_recall_results.append(avg_wasps_recall)
        wasps_precision_results.append(avg_wasps_precision)
        wasps_f1_score_results.append(avg_wasps_f1)
        
        # Visualizes the metrics for the naive sampling approach
        print(f"\033[97mRate : {rate}\033[0m")
        print(f"Naive Sampling")
        print(f"\033[90mRecall:\033[0m {avg_naive_recall:.8f}\n\033[90mPrecision:\033[0m {avg_naive_precision:.8f}\n\033[90mF1 Score:\033[0m {avg_naive_f1:.8f}")
        # Visualizes the metrics for the wasp detection architecture
        print(f"Wasp Detection")
        print(f"\033[90mRecall:\033[0m {avg_wasps_recall:.8f}\n\033[90mPrecision:\033[0m {avg_wasps_precision:.8f}\n\033[90mF1 Score:\033[0m {avg_wasps_f1:.8f}")
        print("\033[92mDone!\033[0m\n")
    
    # Calculates the inverse of each rate
    inverse_rates = [1/rate for rate in rates]
    
    # PLOTS [ using logarithmic scale for the x-axis ] 
    # Recall plot
    plot.figure(figsize=(10, 6))
    plot.plot(inverse_rates, naive_recall_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_recall_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='bold')
    plot.ylabel('Recall', fontweight='bold')
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.ylim(-1, 2)
    plot.show(block=False)
    
    # Precision plot
    plot.figure(figsize=(10, 6))
    plot.plot(inverse_rates, naive_precision_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_precision_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='bold')
    plot.ylabel('Precision', fontweight='bold')
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.ylim(-1, 2)
    plot.show(block=False)
    
    # F1 score plot
    plot.figure(figsize=(10, 6))
    plot.plot(inverse_rates, naive_f1_score_results, marker='o', linestyle='-', linewidth=2, color='blue', label='Naive Sampling')
    plot.plot(inverse_rates, wasps_f1_score_results, marker='o', linestyle='-', linewidth=2, color='green', label='Wasp Detection')
    plot.xlabel('1/R', fontweight='bold')
    plot.ylabel('F1 Score', fontweight='bold')
    plot.xscale('log')  
    plot.grid(True, alpha=0.3, linestyle='--', color='gray')
    plot.legend()
    plot.tight_layout()
    plot.ylim(-1, 2)
    plot.show(block=False)