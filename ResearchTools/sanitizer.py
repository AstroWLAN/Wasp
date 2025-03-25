import os
import pandas as pd

# Sanitizes the dataset from previously inserted headers or useless information [ isolates the true labels ]
def sanitizer():
    try:
        # Retrieves user information
        csv = input("\033[37mFile [ \033[90m.csv \033[37m] : \033[0m")
        header = input("\033[37mHeader? [ \033[90m y | n \033[37m] : \033[0m").lower()
        labels_column = int(input("Labels column \033[0m[ \033[90minteger\033[0m ] : "))
        attack = input("Attack : ").lower()
        print("\033[90mSanitizing dataset\033[0m")
        # Reads the .csv file
        if header == 'y':
            original_dataframe = pd.read_csv(csv, header=0)
        else:
            original_dataframe = pd.read_csv(csv, header=None)
        labels = original_dataframe.iloc[:, labels_column]
        dataframe = pd.DataFrame({'True Labels': labels})
        
        # Retrieves the desktop path
        desktop = os.path.expanduser("~/Desktop")
        output_file = os.path.join(desktop, f"{attack}_TL.csv")

        # Generates the new .csv file
        dataframe.to_csv(output_file, index=False)
        print("\033[92mDone\n\033[0m")
    except Exception as error:
        print(f"\033[91mSomething went wrong 🔥\033[0m\033[90m\n{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mDataset sanitizer\n\033[0m")
    sanitizer()