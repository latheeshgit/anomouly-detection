import socket
import os
import pandas as pd

# List of columns to be read from the CSV file
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

DATA_FILE = r"E:/CloudAnomalyDetectionSystem/data/train/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

def load_portscan_data(file_path):
    """
    Reads only the specific PortScan CSV file, selects columns, and filters 'PortScan' label.
    """
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(file_path, usecols=COLUMNS)
        portscan_df = df[df["Label"] == "PortScan"]
        return portscan_df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()

def port_scan(target_ip="127.0.0.1", target_port=8080):
    """
    Scans the specified IP address for the given port (fixed at 8080)
    and starts sending packets immediately.
    """
    print(f"Starting port scan on {target_ip} for port {target_port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set timeout for connection attempt
    result = sock.connect_ex((target_ip, target_port))
    if result == 0:
        print(f"Port {target_port} is open")
    else:
        print(f"Port {target_port} is closed")
    sock.close()

def main():
    # Read only the specific file
    portscan_data = load_portscan_data(DATA_FILE)
    if portscan_data.empty:
        print("No records labeled 'PortScan' found in the provided CSV file.")
    else:
        print(f"Total PortScan records found: {len(portscan_data)}")

    # Immediately scan only port 8080 on the target IP
    port_scan(target_ip="127.0.0.1", target_port=8080)

if __name__ == "__main__":
    main()
