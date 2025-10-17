import os
import pandas as pd

# Sanitize the ground-truth labels .csv file from useless information -> isolate the true labels [ TL ]
def sanitizer():
    try:
        # User inputs
        csv = input("\033[37mFile [ \033[90m.csv \033[37m] : \033[0m")
        header = input("\033[37mHeader? [ \033[90m y | n \033[37m] : \033[0m").lower()
        labels_column = int(input("Labels column \033[0m[ \033[90minteger\033[0m ] : "))
        attack = input("Attack : ").lower()
        print("\033[90mSanitizing the ground-truth labels source file...\033[0m")
        # Reads the .csv file
        if header == 'y':
            original_dataframe = pd.read_csv(csv, header=0, low_memory=False)
        else:
            original_dataframe = pd.read_csv(csv, header=None, low_memory=False)
        labels = original_dataframe.iloc[:, labels_column]
        dataframe = pd.DataFrame({'True Labels': labels})
        
        # Retrieve the input folder path
        input_dir = os.path.dirname(csv)
        output_file = os.path.join(input_dir, f"{attack}_TL.csv")

        # Generate the new .csv file with the true labels
        dataframe.to_csv(output_file, index=False)
        print("\033[92mDone\n\033[0m")
        
    # Exception handling : log the error in the console
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    print("\n\033[1;37mResearch Kit 🔎\033[0m\n\033[90mGround-truth labels sanitizer\n\033[0m")
    sanitizer()