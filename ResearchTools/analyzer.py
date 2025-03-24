import matplotlib.pyplot as plt
import pandas as pd
import os

# Plots the distribution of benign and malicious packets
def plot_dataset():
    # Gets the user inputs and reads the .csv file
    csv = input("\033[37mFile [ \033[90m.csv \033[37m] : \033[0m")
    header = input("\033[37mHeader? [ \033[90m y | n -→ default is y \033[37m] : \033[0m").lower() == 'y'
    label_column = int(input("Labels column \033[0m[ \033[90minteger\033[0m ] : "))
    attack = input("Attack : ")
    try:
        header_bool = 0 if header else None
        dataframe = pd.read_csv(csv, header=header_bool)
    except Exception as e:
        print(f"\033[91m{e} 🔥\033[0m")
        return 
    # Verifies if the provided column index is legit
    if label_column < 0 or label_column >= len(dataframe.columns):
        print(f"Column index {label_column} is out of range (0-{len(dataframe.columns)-1}).")
        return  
    # Gets the requested column
    column = dataframe.iloc[:, label_column]
    # Counts the number of benign and malicious packets
    benign = len(column[column == 0])
    malicious = len(column[column == 1])
    total = benign + malicious
    # Computes the percentages
    benign_percentage = (benign / total) * 100
    malicious_percentage = (malicious / total) * 100
    
    # Generates the labels for the plot
    labels = ['Benign', 'Malicious']
    counts = [benign, malicious]
    percentages = [benign_percentage, malicious_percentage]
    # Creates an histogram
    plt.figure(figsize=(10, 6))
    # Create the bar plot
    bars = plt.bar(labels, counts, color=['green', 'red'])
    # Make labels bold using font properties
    plt.xticks(fontweight='semibold')
    # Removes the box around the graph
    ax = plt.gca()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    # Attaches the packet count and percentage labels over each bar of the histogram
    for _, (bar, count, percentage) in enumerate(zip(bars, counts, percentages)):
        # Position boxes at the bottom with some padding
        max_height = max([b.get_height() for b in bars])
        y_pos = max_height * 0.075  # 10% of the maximum bar height
        plt.text(bar.get_x() + bar.get_width()/2., y_pos,
                f'{count}\n$\\mathbf{{{percentage:.1f}\\%}}$',
                ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.7', facecolor='white', alpha=1))
    # Attaches labels and title to the plot
    plt.ylabel('Packets', fontweight='semibold')
    plt.title(f'{attack} Dataset Composition', fontweight='semibold')
    # Visualizes the plot
    plt.tight_layout()
    # Saves the plot to the \Results folder 
    plt.savefig(f'Results/{attack.lower()} distribution.png')
    print("\033[90mPlot saved in the \Result folder\033[0m\n\033[92mDone!\033[0m")
    plt.show()

# MAIN
if __name__ == "__main__":
    print("\n\033[37mResearchKit 🔎\033[0m\n\033[90mDataset Analyzer\n\033[0m")
    plot_dataset() 