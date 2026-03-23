import os
import pandas as pd
import socket
import time
import sys

# Specific file to read
DATA_FILE = r"E:/CloudAnomalyDetectionSystem/data/train/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

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

def load_ddos_data(file_path):
    """Reads only the specified CSV file, selects columns, and filters 'DDoS' label."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(file_path, usecols=COLUMNS)
        ddos_df = df[df["Label"] == "DDoS"]
        return ddos_df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()

def ddos_attack(target_ip="127.0.0.1", target_port=8080):
    """Simulates a DDoS attack by continuously sending UDP packets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_data = b'\x00' * 1024  # 1KB of data
        print(f"Starting DDoS attack simulation on {target_ip}:{target_port}")

        while True:
            sock.sendto(bytes_data, (target_ip, target_port))
            print(f"Packet sent to {target_ip}:{target_port}")
    except KeyboardInterrupt:
        print("\nDDoS attack simulation stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"Error during DDoS attack: {e}")
        sys.exit(1)

def main():
    # Read only the specific file
    ddos_data = load_ddos_data(DATA_FILE)
    if ddos_data.empty:
        print("No records labeled 'DDoS' found in the provided CSV file.")
        return
    else:
        print(f"Total DDoS records found: {len(ddos_data)}")

    try:
        target_port = int(ddos_data.iloc[0]["Destination Port"])
    except Exception as e:
        print(f"Error extracting target port from data: {e}")
        target_port = 8080

    ddos_attack(target_port=target_port)

if __name__ == "__main__":
    main()
