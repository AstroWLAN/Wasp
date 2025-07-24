import os
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Plots the distribution of benign and malicious packets in a dataset
def composition():
    # PARAMETERS 
    desktop = str(Path.home() / "Desktop")
    col_labels = 0  
    
    # Gets the user inputs and reads the .csv file
    csv = input("\033[37mFile [ \033[90m.csv \033[37m] : \033[0m")
    attack = input("Attack : ")
    training = int(input("\033[37mTraining packets [ \033[90mremoves the first N packets used for training\033[37m ] : \033[0m"))
    
    try:
        # Reads the .csv file and removes the first 'training' packets
        dataframe = pd.read_csv(csv)
        dataframe = dataframe.iloc[training:]
        column = dataframe.iloc[:, col_labels]
        
        # Counts the number of benign and malicious packets and computes the percentages
        benign = len(column[column == 0])
        malicious = len(column[column == 1])
        total = benign + malicious
        benign_percentage = (benign / total) * 100
        malicious_percentage = (malicious / total) * 100
    
        # Configures the plot
        labels = ['Benign', 'Malicious']
        counts = [benign, malicious]
        percentages = [benign_percentage, malicious_percentage]
        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, counts, color=['green', 'red'])
        plt.xticks(fontweight='semibold')
        
        # Inserts the dataset information on the plot
        for _, (bar, count, percentage) in enumerate(zip(bars, counts, percentages)):
            max_height = max([b.get_height() for b in bars])
            y_pos = max_height * 0.075 
            plt.text(bar.get_x() + bar.get_width()/2., y_pos, f'{count}\n$\\mathbf{{{percentage:.1f}\\%}}$', 
                     ha='center', va='center', 
                     bbox=dict(boxstyle='round,pad=0.7', facecolor='white', alpha=1))
        
        # Attaches the labels and title to the plot
        plt.ylabel('Packets', fontweight='semibold', labelpad=10)
        plt.title(f'{attack} Dataset Composition', fontweight='semibold', pad=10)
        plt.tight_layout()
        
        # Saves the plot to the desktop
        plt.savefig(os.path.join(desktop, f'{attack}_composition.png'), dpi=384)
        print(f"\033[90mPlot saved to desktop as '{attack}_composition.png'\033[0m\n\033[92mDone\033[0m")
        
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearchKit 🔎\033[0m\n\033[90mDataset composition\n\033[0m")
    composition()  