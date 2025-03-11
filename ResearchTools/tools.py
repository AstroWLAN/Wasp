import math
import numpy as np
import matplotlib.pyplot as plot

# Performs a probabilistic sampling of the packets 
def naive_sampling (predictions, rate, true_labels):
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
    print(f"\033[97mPrecision = {precision:.8f}\033[0m")
    print(f"\033[97mRecall = {recall:.8f}\033[0m")
    print(f"\033[97mF1 Score = {f1:.8f}\033[0m")
    print(f"\033[97mAccuracy = {accuracy:.8f}\033[0m")
    print(f"\033[92mDone!\033[0m\n")
    return accuracy, precision, recall, f1

# Performs a sampling procedure that take into account the observed malicious flows
def wasps_detection (predictions, flowIDs, true_labels, rate = 1):
    # Sets of observed malicious flows
    wasp_nest = set()
    # Sampling parameters
    N = len(predictions)
    M = math.floor(N * rate)
    print(f"\n\033[90mRunning the wasps detection procedure with a rate of {rate:.2f}\033[0m")
    # Generates a duplicate of the predictions for the wasp_predictions [ will be modified later ]
    wasp_predictions = predictions.copy()
    # Selects M random indices [ the indices of the packets to be sampled and left unchanged ]
    indices = np.random.choice(N, size=M, replace=False)
    
    # Scans the sampled packets to populate the wasp_nest
    for i in indices:
        if predictions[i] == 1:  # Only add malicious packets to wasp_nest
            wasp_nest.add(flowIDs[i])
    
    # Generates a sampling mask for the indices that will be processed
    sampling_mask = np.ones(N, dtype=bool)
    sampling_mask[indices] = False
    
    # Process each prediction based on the sampling mask and wasp_nest logic
    for i in range(N):
        if not sampling_mask[i]:
            # Left unchanged [ sampled from the original predictions ]
            continue
        
        # Reads the prediction and the flowID for the current packet
        value = predictions[i]
        flow_id = flowIDs[i]
        
        # Malicious packet whose flowID has been observed and registered in the wasp_nest
        if value == 1 and flow_id in wasp_nest:
            # Leaves it unchanged
            wasp_predictions[i] = 1
        # Malicious packet whose flowID has not been observed and registered in the wasp_nest
        elif value == 1 and flow_id not in wasp_nest:
            # Set to 0 since it's not in the wasp_nest
            wasp_predictions[i] = 0
        # Benign packet whose flowID belongs to the wasp_nest
        elif value == 0 and flow_id in wasp_nest:
            # Labels it as malicious
            wasp_predictions[i] = 1
        else:
            # Leaves it unchanged
            wasp_predictions[i] = 0
    
    # Calculates the difference between original and sampled predictions
    different_count = np.sum(predictions != wasp_predictions)
    difference_percentage = (different_count / N) * 100
    
    # Prints some useful information about the sampling procedure
    print(f"\033[97mPackets sampled\033[90m [ unchanged predictions ] \033[97m: {M} -→ {(M/N)*100:.2f}%\033[0m")
    print(f"\033[97mPackets modified\033[90m [ based on wasp_nest logic ] \033[97m: {different_count} -→ {difference_percentage:.2f}%\033[0m")
    print(f"\033[97mTotal flows in wasp_nest: {len(wasp_nest)}\033[0m")
    
    # Computes the precision and recall metrics of the sampling procedure
    if len(true_labels) != len(wasp_predictions):
        print(f"\033[91mThere is a mismatch between the number of true labels and the number of sampled predictions 🔥\033[0m\n\033[90mLook at the provided files for possible errors\033[0m")
        return
    
    # Computes the metrics 
    true_positives = np.sum((wasp_predictions == 1) & (true_labels == 1))
    false_positives = np.sum((wasp_predictions == 1) & (true_labels == 0))
    false_negatives = np.sum((wasp_predictions == 0) & (true_labels == 1))
    true_negatives = np.sum((wasp_predictions == 0) & (true_labels == 0))
    
    # Computes the precision [ TP / (TP + FP) ] 
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    # Computes the recall [ TP / (TP + FN) ]
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    # Computes the F1 score [ 2 * (precision * recall) / (precision + recall) ] 
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    # Computes the accuracy [ (TP + TN) / (TP + TN + FP + FN) ]
    accuracy = (true_positives + true_negatives) / (true_positives + true_negatives + false_positives + false_negatives) if N > 0 else 0
    
    # Prints the metrics
    print(f"\033[97mPrecision = {precision:.8f}\033[0m")
    print(f"\033[97mRecall = {recall:.8f}\033[0m")
    print(f"\033[97mF1 Score = {f1:.8f}\033[0m")
    print(f"\033[97mAccuracy = {accuracy:.8f}\033[0m")
    print(f"\033[92mDone!\033[0m\n")
    
    return accuracy, precision, recall, f1

# Computes some metrics to evaluate the performance of the detection system 
# Since the sampling is RANDOMIC each metric is computed multiple times and then averaged
def performance_analysis (predictions, flowIDs, true_labels, rates = None, iterations = 10):
    # Results of the tests - separate lists for each method
    naive_recall_results = []
    naive_precision_results = []
    naive_f1_score_results = []
    
    wasps_recall_results = []
    wasps_precision_results = []
    wasps_f1_score_results = []
    
    # Sets the default rates if none are provided
    if rates is None:
        rates = [0.00001, 0.0001, 0.001, 0.01, 0.1, 0.25, 0.5, 1]
    
    print(f"\033[90mCollecting the performance of the architectures\033[0m")
    for rate in rates:
        print(f"\033[90mTesting the systems with a {rate} sampling rate\033[0m")
        # Initialize accumulators for averaging
        total_naive_recall = 0
        total_naive_precision = 0
        total_naive_f1 = 0
        
        total_wasps_recall = 0
        total_wasps_precision = 0
        total_wasps_f1 = 0
        
        for _ in range(iterations):
            # Naive sampling
            sampling_accuracy, sampling_precision, sampling_recall, sampling_f1 = naive_sampling(predictions, rate, true_labels)
            # Wasps detection
            wasps_accuracy, wasps_precision, wasps_recall, wasps_f1 = wasps_detection(predictions, flowIDs, true_labels, rate)
            
            # Accumulate results
            total_naive_recall += sampling_recall
            total_naive_precision += sampling_precision
            total_naive_f1 += sampling_f1
            
            total_wasps_recall += wasps_recall
            total_wasps_precision += wasps_precision
            total_wasps_f1 += wasps_f1
        
        # Calculate averages
        avg_naive_recall = total_naive_recall / iterations
        avg_naive_precision = total_naive_precision / iterations
        avg_naive_f1 = total_naive_f1 / iterations
        
        avg_wasps_recall = total_wasps_recall / iterations
        avg_wasps_precision = total_wasps_precision / iterations
        avg_wasps_f1 = total_wasps_f1 / iterations
        
        # Collects the average results in separate lists
        naive_recall_results.append(avg_naive_recall)
        naive_precision_results.append(avg_naive_precision)
        naive_f1_score_results.append(avg_naive_f1)
        
        wasps_recall_results.append(avg_wasps_recall)
        wasps_precision_results.append(avg_wasps_precision)
        wasps_f1_score_results.append(avg_wasps_f1)
    
    # Calculate inverse for each rate
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
    plot.show(block=False)