#!/usr/bin/env python3

import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
import sys

def analyze_dataset(csv_path, header=None, label_column=0, has_header=False, training_packets=0):
    """
    Analyzes a CSV file containing network packet labels to count malicious packets.
    
    Args:
        csv_path (str): Path to the CSV file
        header (int or None): Header parameter for pd.read_csv
        label_column (int): Column index containing the labels
        has_header (bool): Whether the CSV file has a header row
        training_packets (int): Number of initial packets to exclude (used for training)
    
    Returns:
        dict: Dictionary containing analysis results
    """
    print(f"\n[*] Analyzing dataset: {os.path.basename(csv_path)}")
    
    try:
        # Load the CSV file
        if has_header:
            df = pd.read_csv(csv_path, header=0, low_memory=False)
        else:
            df = pd.read_csv(csv_path, header=header, low_memory=False)
        
        # Extract labels
        labels = df.iloc[:, label_column].values
        
        # Count total packets (before excluding training packets)
        total_original = len(labels)
        
        # Exclude training packets if specified
        if training_packets > 0:
            if training_packets >= total_original:
                print(f"[!] Warning: Training packets ({training_packets}) exceeds or equals total packets ({total_original})")
                training_packets = 0
            else:
                print(f"[*] Excluding first {training_packets} packets used for training")
                labels = labels[training_packets:]
        
        # Count total packets (after excluding training packets)
        total_packets = len(labels)
        
        # Count malicious packets (labeled as 1)
        malicious_packets = np.sum(labels == 1)
        
        # Count benign packets (labeled as 0)
        benign_packets = np.sum(labels == 0)
        
        # Calculate percentages
        malicious_percentage = (malicious_packets / total_packets) * 100 if total_packets > 0 else 0
        benign_percentage = (benign_packets / total_packets) * 100 if total_packets > 0 else 0
        
        # Prepare results
        results = {
            "total_original": total_original,
            "training_packets": training_packets,
            "total_packets": total_packets,
            "malicious_packets": malicious_packets,
            "benign_packets": benign_packets,
            "malicious_percentage": malicious_percentage,
            "benign_percentage": benign_percentage
        }
        
        return results
    
    except Exception as e:
        print(f"[!] Error analyzing dataset: {str(e)}")
        return None

def print_results(results, dataset_name=None):
    """
    Prints the analysis results in a formatted way.
    
    Args:
        results (dict): Dictionary containing analysis results
        dataset_name (str, optional): Name of the dataset
    """
    if not results:
        return
    
    header = "\n[+] Dataset Analysis Results:"
    if dataset_name:
        header = f"\n[+] Dataset Analysis Results for {dataset_name}:"
    print(header)
    
    if results["training_packets"] > 0:
        print(f"    Original total packets: {results['total_original']}")
        print(f"    Training packets excluded: {results['training_packets']}")
    print(f"    Analyzed packets: {results['total_packets']}")
    print(f"    Malicious packets: {results['malicious_packets']} ({results['malicious_percentage']:.2f}%)")
    print(f"    Benign packets: {results['benign_packets']} ({results['benign_percentage']:.2f}%)")

def plot_distribution(results, output_path=None):
    """
    Creates a pie chart showing the distribution of malicious and benign packets.
    
    Args:
        results (dict): Dictionary containing analysis results
        output_path (str, optional): Path to save the plot. If None, the plot is displayed.
    """
    if not results:
        return
    
    # Create pie chart
    labels = ['Malicious', 'Benign']
    sizes = [results['malicious_packets'], results['benign_packets']]
    colors = ['#ff6961', '#77dd77']
    explode = (0.1, 0)  # explode the 1st slice (Malicious)
    
    plt.figure(figsize=(10, 7))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    
    title = 'Distribution of Packet Types'
    if results["training_packets"] > 0:
        title += f' (Excluding {results["training_packets"]} Training Packets)'
    plt.title(title)
    
    if output_path:
        plt.savefig(output_path)
        print(f"[+] Plot saved to: {output_path}")
    else:
        plt.show()

def plot_comparative_histogram(all_results, output_path=None):
    """
    Creates a comparative histogram showing malicious and benign packet counts across datasets.
    
    Args:
        all_results (dict): Dictionary mapping dataset names to their analysis results
        output_path (str, optional): Path to save the plot. If None, the plot is displayed.
    """
    if not all_results:
        return
    
    # Prepare data for plotting
    datasets = list(all_results.keys())
    malicious_counts = [all_results[dataset]['malicious_packets'] for dataset in datasets]
    benign_counts = [all_results[dataset]['benign_packets'] for dataset in datasets]
    
    # Set up the figure
    plt.figure(figsize=(12, 8))
    
    # Set width of bars
    bar_width = 0.35
    
    # Set position of bars on x axis
    r1 = np.arange(len(datasets))
    r2 = [x + bar_width for x in r1]
    
    # Create bars
    plt.bar(r1, malicious_counts, color='#ff6961', width=bar_width, edgecolor='grey', label='Malicious')
    plt.bar(r2, benign_counts, color='#77dd77', width=bar_width, edgecolor='grey', label='Benign')
    
    # Add labels and title
    plt.xlabel('Datasets', fontweight='bold', fontsize=12)
    plt.ylabel('Packet Count', fontweight='bold', fontsize=12)
    plt.title('Comparison of Malicious and Benign Packets Across Datasets', fontweight='bold', fontsize=14)
    
    # Add xticks on the middle of the group bars
    plt.xticks([r + bar_width/2 for r in range(len(datasets))], datasets)
    
    # Add a legend
    plt.legend()
    
    # Add value labels on top of each bar
    for i, v in enumerate(malicious_counts):
        plt.text(i - 0.1, v + 0.1, str(v), color='black', fontweight='bold')
    
    for i, v in enumerate(benign_counts):
        plt.text(i + bar_width - 0.1, v + 0.1, str(v), color='black', fontweight='bold')
    
    # Adjust layout
    plt.tight_layout()
    
    # Save or display the plot
    if output_path:
        plt.savefig(output_path)
        print(f"[+] Comparative histogram saved to: {output_path}")
    else:
        plt.show()

def plot_percentage_histogram(all_results, output_path=None):
    """
    Creates a comparative histogram showing malicious and benign packet percentages across datasets.
    
    Args:
        all_results (dict): Dictionary mapping dataset names to their analysis results
        output_path (str, optional): Path to save the plot. If None, the plot is displayed.
    """
    if not all_results:
        return
    
    # Prepare data for plotting
    datasets = list(all_results.keys())
    malicious_percentages = [all_results[dataset]['malicious_percentage'] for dataset in datasets]
    benign_percentages = [all_results[dataset]['benign_percentage'] for dataset in datasets]
    
    # Set up the figure
    plt.figure(figsize=(12, 8))
    
    # Set width of bars
    bar_width = 0.35
    
    # Set position of bars on x axis
    r1 = np.arange(len(datasets))
    r2 = [x + bar_width for x in r1]
    
    # Create bars
    plt.bar(r1, malicious_percentages, color='#ff6961', width=bar_width, edgecolor='grey', label='Malicious')
    plt.bar(r2, benign_percentages, color='#77dd77', width=bar_width, edgecolor='grey', label='Benign')
    
    # Add labels and title
    plt.xlabel('Datasets', fontweight='bold', fontsize=12)
    plt.ylabel('Percentage (%)', fontweight='bold', fontsize=12)
    plt.title('Comparison of Malicious and Benign Packet Percentages Across Datasets', fontweight='bold', fontsize=14)
    
    # Add xticks on the middle of the group bars
    plt.xticks([r + bar_width/2 for r in range(len(datasets))], datasets)
    
    # Add a legend
    plt.legend()
    
    # Add value labels on top of each bar
    for i, v in enumerate(malicious_percentages):
        plt.text(i - 0.1, v + 1, f"{v:.1f}%", color='black', fontweight='bold')
    
    for i, v in enumerate(benign_percentages):
        plt.text(i + bar_width - 0.1, v + 1, f"{v:.1f}%", color='black', fontweight='bold')
    
    # Adjust layout
    plt.tight_layout()
    
    # Save or display the plot
    if output_path:
        plt.savefig(output_path)
        print(f"[+] Percentage histogram saved to: {output_path}")
    else:
        plt.show()

def multi_dataset_analysis():
    """
    Interactive function to analyze multiple datasets and create comparative visualizations.
    """
    all_results = {}
    datasets = []
    
    print("\n[*] Multiple Dataset Analysis Mode")
    print("[*] You will be prompted to enter paths to multiple CSV files")
    print("[*] Enter 'done' when you have finished adding datasets")
    
    while True:
        # Get dataset path
        csv_path = input("\n[?] Enter path to CSV file (or 'done' to finish): ")
        if csv_path.lower() == 'done':
            break
        
        # Check if file exists
        if not os.path.exists(csv_path):
            print(f"[!] Error: File not found: {csv_path}")
            continue
        
        # Get dataset name
        dataset_name = input("[?] Enter a name for this dataset: ")
        if not dataset_name:
            dataset_name = os.path.basename(csv_path)
        
        # Ask if the file has a header
        has_header_input = input("[?] Does this CSV have a header row? (y/n, default: n): ")
        has_header = has_header_input.lower() == 'y'
        
        # Ask for label column
        label_column = 0
        label_column_input = input("[?] Enter the column index containing labels (default: 0): ")
        if label_column_input.strip():
            try:
                label_column = int(label_column_input)
            except ValueError:
                print("[!] Invalid input. Using default value of 0.")
        
        # Ask for training packets
        training_packets = 0
        training_packets_input = input("[?] Enter number of packets used for training (default: 0): ")
        if training_packets_input.strip():
            try:
                training_packets = int(training_packets_input)
            except ValueError:
                print("[!] Invalid input. Using default value of 0.")
        
        # Analyze the dataset
        results = analyze_dataset(
            csv_path,
            header=0 if has_header else None,
            label_column=label_column,
            has_header=has_header,
            training_packets=training_packets
        )
        
        if results:
            all_results[dataset_name] = results
            datasets.append(dataset_name)
            print_results(results, dataset_name)
    
    # Check if we have any results
    if not all_results:
        print("[!] No datasets were successfully analyzed.")
        return
    
    # Ask what type of visualization to create
    print("\n[*] Available Visualization Options:")
    print("    1. Individual pie charts for each dataset")
    print("    2. Comparative histogram (packet counts)")
    print("    3. Comparative histogram (percentages)")
    print("    4. All visualizations")
    
    viz_choice = input("[?] Enter your choice (1-4, default: 4): ")
    
    # Default to all visualizations
    if not viz_choice.strip() or viz_choice not in ['1', '2', '3', '4']:
        viz_choice = '4'
    
    # Ask if they want to save the plots
    save_plots = input("[?] Do you want to save the plots? (y/n, default: n): ")
    save_plots = save_plots.lower() == 'y'
    
    output_dir = None
    if save_plots:
        output_dir = input("[?] Enter directory to save plots (default: current directory): ")
        if not output_dir.strip():
            output_dir = '.'
        
        # Create directory if it doesn't exist
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"[*] Created directory: {output_dir}")
            except Exception as e:
                print(f"[!] Error creating directory: {str(e)}")
                output_dir = '.'
    
    # Generate visualizations based on user choice
    if viz_choice in ['1', '4']:
        for dataset_name, results in all_results.items():
            output_path = None
            if save_plots:
                output_path = os.path.join(output_dir, f"{dataset_name}_pie.png")
            
            plt.figure()
            plot_distribution(results, output_path)
            if not save_plots:
                plt.show()
    
    if viz_choice in ['2', '4']:
        output_path = None
        if save_plots:
            output_path = os.path.join(output_dir, "comparative_histogram_counts.png")
        
        plot_comparative_histogram(all_results, output_path)
        if not save_plots:
            plt.show()
    
    if viz_choice in ['3', '4']:
        output_path = None
        if save_plots:
            output_path = os.path.join(output_dir, "comparative_histogram_percentages.png")
        
        plot_percentage_histogram(all_results, output_path)
        if not save_plots:
            plt.show()
    
    print("\n[+] Analysis complete!")

def menu_driven_interface():
    """
    Provides a menu-driven interface for analyzing datasets and plotting results.
    """
    # Storage for analyzed datasets
    analyzed_datasets = {}
    current_dataset = None
    current_dataset_name = None
    
    while True:
        print("\n" + "="*50)
        print("NETWORK PACKET DATASET ANALYZER".center(50))
        print("="*50)
        print("\n[1] Analyze a dataset")
        print("[2] Plot results")
        print("[3] Quit")
        
        choice = input("\n[?] Enter your choice (1-3): ")
        
        if choice == '1':
            # Analyze a dataset
            csv_path = input("\n[?] Enter path to CSV file: ")
            
            # Check if file exists
            if not os.path.exists(csv_path):
                print(f"[!] Error: File not found: {csv_path}")
                continue
            
            # Get dataset name
            dataset_name = input("[?] Enter a name for this dataset (default: filename): ")
            if not dataset_name:
                dataset_name = os.path.basename(csv_path)
            
            # Ask if the file has a header
            has_header_input = input("[?] Does this CSV have a header row? (y/n, default: n): ")
            has_header = has_header_input.lower() == 'y'
            
            # Ask for label column
            label_column = 0
            label_column_input = input("[?] Enter the column index containing labels (default: 0): ")
            if label_column_input.strip():
                try:
                    label_column = int(label_column_input)
                except ValueError:
                    print("[!] Invalid input. Using default value of 0.")
            
            # Ask for training packets
            training_packets = 0
            training_packets_input = input("[?] Enter number of packets used for training (default: 0): ")
            if training_packets_input.strip():
                try:
                    training_packets = int(training_packets_input)
                except ValueError:
                    print("[!] Invalid input. Using default value of 0.")
            
            # Analyze the dataset
            results = analyze_dataset(
                csv_path,
                header=0 if has_header else None,
                label_column=label_column,
                has_header=has_header,
                training_packets=training_packets
            )
            
            if results:
                analyzed_datasets[dataset_name] = results
                current_dataset = results
                current_dataset_name = dataset_name
                print_results(results, dataset_name)
                print(f"\n[+] Dataset '{dataset_name}' has been analyzed and stored.")
            
        elif choice == '2':
            # Plot results
            if not analyzed_datasets:
                print("\n[!] No datasets have been analyzed yet. Please analyze a dataset first.")
                continue
            
            print("\n[*] Available Datasets:")
            for i, name in enumerate(analyzed_datasets.keys(), 1):
                print(f"    [{i}] {name}")
            
            print("\n[*] Plot Options:")
            print("    [1] Plot single dataset (pie chart)")
            print("    [2] Plot comparative histogram (packet counts)")
            print("    [3] Plot comparative histogram (percentages)")
            print("    [4] Return to main menu")
            
            plot_choice = input("\n[?] Enter your choice (1-4): ")
            
            if plot_choice == '1':
                # Plot single dataset
                if len(analyzed_datasets) == 1:
                    dataset_name = list(analyzed_datasets.keys())[0]
                else:
                    dataset_idx = input("[?] Enter dataset number to plot: ")
                    try:
                        idx = int(dataset_idx) - 1
                        if 0 <= idx < len(analyzed_datasets):
                            dataset_name = list(analyzed_datasets.keys())[idx]
                        else:
                            print("[!] Invalid dataset number.")
                            continue
                    except ValueError:
                        print("[!] Invalid input.")
                        continue
                
                # Ask if they want to save the plot
                save_plot = input("[?] Save the plot? (y/n, default: n): ")
                save_plot = save_plot.lower() == 'y'
                
                output_path = None
                if save_plot:
                    output_dir = input("[?] Enter directory to save plot (default: current directory): ")
                    if not output_dir.strip():
                        output_dir = '.'
                    
                    # Create directory if it doesn't exist
                    if not os.path.exists(output_dir):
                        try:
                            os.makedirs(output_dir)
                            print(f"[*] Created directory: {output_dir}")
                        except Exception as e:
                            print(f"[!] Error creating directory: {str(e)}")
                            output_dir = '.'
                    
                    output_path = os.path.join(output_dir, f"{dataset_name}_pie.png")
                
                plot_distribution(analyzed_datasets[dataset_name], output_path)
                
            elif plot_choice == '2' or plot_choice == '3':
                # Plot comparative histogram
                if len(analyzed_datasets) < 2:
                    print("[!] Need at least 2 datasets for comparative histogram.")
                    continue
                
                # Ask if they want to select specific datasets
                select_datasets = input("[?] Select specific datasets? (y/n, default: n): ")
                select_datasets = select_datasets.lower() == 'y'
                
                datasets_to_plot = {}
                if select_datasets:
                    print("[*] Enter dataset numbers separated by commas (e.g., 1,3,4):")
                    dataset_indices = input("[?] Datasets to include: ")
                    try:
                        indices = [int(idx.strip()) - 1 for idx in dataset_indices.split(',')]
                        dataset_names = list(analyzed_datasets.keys())
                        for idx in indices:
                            if 0 <= idx < len(dataset_names):
                                name = dataset_names[idx]
                                datasets_to_plot[name] = analyzed_datasets[name]
                        
                        if not datasets_to_plot:
                            print("[!] No valid datasets selected.")
                            continue
                    except ValueError:
                        print("[!] Invalid input.")
                        continue
                else:
                    datasets_to_plot = analyzed_datasets
                
                # Ask if they want to save the plot
                save_plot = input("[?] Save the plot? (y/n, default: n): ")
                save_plot = save_plot.lower() == 'y'
                
                output_path = None
                if save_plot:
                    output_dir = input("[?] Enter directory to save plot (default: current directory): ")
                    if not output_dir.strip():
                        output_dir = '.'
                    
                    # Create directory if it doesn't exist
                    if not os.path.exists(output_dir):
                        try:
                            os.makedirs(output_dir)
                            print(f"[*] Created directory: {output_dir}")
                        except Exception as e:
                            print(f"[!] Error creating directory: {str(e)}")
                            output_dir = '.'
                    
                    plot_type = "counts" if plot_choice == '2' else "percentages"
                    output_path = os.path.join(output_dir, f"comparative_histogram_{plot_type}.png")
                
                if plot_choice == '2':
                    plot_comparative_histogram(datasets_to_plot, output_path)
                else:
                    plot_percentage_histogram(datasets_to_plot, output_path)
                
            elif plot_choice == '4':
                # Return to main menu
                continue
                
            else:
                print("[!] Invalid choice.")
            
        elif choice == '3':
            # Quit
            print("\n[+] Thank you for using the Network Packet Dataset Analyzer. Goodbye!")
            break
            
        else:
            print("\n[!] Invalid choice. Please enter 1, 2, or 3.")

def main():
    parser = argparse.ArgumentParser(description='Analyze network packet dataset to count malicious packets.')
    parser.add_argument('--csv_path', help='Path to the CSV file containing packet labels')
    parser.add_argument('--has-header', action='store_true', help='CSV file has a header row')
    parser.add_argument('--label-column', type=int, default=0, help='Column index containing the labels (default: 0)')
    parser.add_argument('--training-packets', type=int, default=0, 
                        help='Number of initial packets to exclude (used for training)')
    parser.add_argument('--plot', action='store_true', help='Generate a pie chart visualization')
    parser.add_argument('--output', help='Path to save the plot (only used with --plot)')
    parser.add_argument('--interactive', action='store_true', 
                        help='Interactive mode: prompt for training packets count')
    parser.add_argument('--multi', action='store_true',
                        help='Analyze multiple datasets and create comparative visualizations')
    parser.add_argument('--menu', action='store_true',
                        help='Launch menu-driven interface')
    
    args = parser.parse_args()
    
    # Check if menu-driven interface is requested
    if args.menu or len(sys.argv) == 1:  # Default to menu if no args provided
        menu_driven_interface()
        return
    
    # Check if multi-dataset mode is requested
    if args.multi:
        multi_dataset_analysis()
        return
    
    # Single dataset mode requires a CSV path
    if not args.csv_path:
        print("[!] Error: CSV path is required for single dataset analysis.")
        print("[*] Use --multi for multi-dataset analysis mode or --menu for menu-driven interface.")
        return
    
    # Verify the file exists
    if not os.path.exists(args.csv_path):
        print(f"[!] Error: File not found: {args.csv_path}")
        return
    
    # Interactive mode: ask for training packets
    training_packets = args.training_packets
    if args.interactive:
        try:
            user_input = input("\n[?] Enter number of packets used for training (default: 0): ")
            if user_input.strip():
                training_packets = int(user_input)
                print(f"[*] Will exclude first {training_packets} packets from analysis")
        except ValueError:
            print("[!] Invalid input. Using default value of 0.")
            training_packets = 0
    
    # Analyze the dataset
    results = analyze_dataset(
        args.csv_path, 
        header=0 if args.has_header else None,
        label_column=args.label_column,
        has_header=args.has_header,
        training_packets=training_packets
    )
    
    # Print results
    print_results(results)
    
    # Generate plot if requested
    if args.plot:
        plot_distribution(results, args.output)

if __name__ == "__main__":
    main()
