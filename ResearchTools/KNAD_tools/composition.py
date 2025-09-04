import os
import pandas as pd
import matplotlib.pyplot as plt

# Analyze and visualize the composition of benign vs malicious packets in a dataset
def composition():
    try:
        # User inputs
        csv = input("\033[37mFile [ \033[90m.csv \033[37m] : \033[0m")
        attack = input("Attack : ").lower()
        print("\033[90mAnalyzing dataset composition...\033[0m")

        # Parameters
        col_labels = 0

        # Reads the .csv file
        dataframe = pd.read_csv(csv)
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

        # Retrieve the input folder path and save the plot there
        input_dir = os.path.dirname(csv)
        plt.savefig(os.path.join(input_dir, f'{attack}_composition.png'), dpi=384)
        print("\033[92mDone\n\033[0m")
        print(f"\033[90mPlot saved to input folder as '{attack}_composition.png'\033[0m")

    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mDataset composition\n\033[0m")
    composition()  