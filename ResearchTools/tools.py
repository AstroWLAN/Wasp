import numpy as np
import math
import matplotlib.pyplot as plt
import seaborn as sns

# Set seaborn style
sns.set_theme(style="whitegrid")

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
    print(f"\033[97mPrecision = {precision:.8f}\033[0m")
    print(f"\033[97mRecall = {recall:.8f}\033[0m")
    print(f"\033[97mF1 Score = {f1:.8f}\033[0m")
    print(f"\033[97mAccuracy = {accuracy:.8f}\033[0m")
    print(f"\033[92mDone!\033[0m\n")
    return accuracy, precision, recall, f1

# Performs a sampling procedure that take into account the observed malicious flows
def wasps_detection (predictions, true_labels, rate = 1):
    global sampled_predictions
    print("\n\033[90mRunning wasps detection\033[0m")
    print(f"\033[92mDone!\n")
    return 

# Computes some metrics to evaluate the performance of the detection system
def performance_analysis (predictions, true_labels, rates = None):
    # Results of the tests
    recall_results = []
    precision_results = []
    f1_score_results = []
    # Sets the default rates if none are provided
    if rates is None:
        rates = [0.01, 0.1, 0.25, 0.5, 0.75, 1]
    
    print(f"\033[90mCollecting the performance of the architectures\033[0m")
    for rate in rates:
        print(f"\033[90mTesting the systems with a {rate} sampling rate\033[0m")
        # Naive sampling
        sampling_accuracy, sampling_precision, sampling_recall, sampling_f1 = naive_sampling(predictions, rate, true_labels)
        # Wasps detection
        wasps_accuracy, wasps_precision, wasps_recall, wasps_f1 = wasps_detection(predictions, true_labels, rate)
        # Collects the results
        recall_results.append(sampling_recall)
        precision_results.append(sampling_precision)
        f1_score_results.append(sampling_f1)
        recall_results.append(wasps_recall)
        precision_results.append(wasps_precision)
        f1_score_results.append(wasps_f1)
        
    # Generates the recall plot
    plt.figure(figsize=(10, 6))
    # Calculate inverse for each rate
    inverse_rates = [1/rate for rate in rates]
    plt.plot(inverse_rates, recall_results, marker='o', linestyle='-', linewidth=2, label='Recall')
    plt.xlabel('1/R')
    plt.ylabel('Recall')
    plt.grid(True, alpha=0.3, linestyle='--', color='gray')
    # Add annotations for each data point
    for i, (x, y) in enumerate(zip(inverse_rates, recall_results)):
        plt.annotate(f'R: {rates[i]}\nRecall: {y:.3f}', 
                    xy=(x, y), 
                    xytext=(10, 0), 
                    textcoords='offset points',
                    fontsize=8)
    
    # Add legend explaining R = sampling rate
    plt.text(0.95, 0.95, 'R = Sampling Rate', 
             transform=plt.gca().transAxes, 
             fontsize=10, 
             verticalalignment='top', 
             horizontalalignment='right',
             bbox=dict(boxstyle='round,pad=0.25', 
                      facecolor='white', 
                      alpha=0.8,
                      edgecolor='black',
                      linewidth=1))
    
    plt.tight_layout()
    plt.savefig('recall_vs_inverse_sampling_rate.png')
    plt.show(block=False)