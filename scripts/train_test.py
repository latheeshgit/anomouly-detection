import os
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import numpy as np

# Define the directory where data is stored using relative paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cleaned_data_dir = os.path.join(BASE_DIR, 'data', 'cleaned')
normalized_data_dir = os.path.join(BASE_DIR, 'data', 'normalized')
train_data_dir = os.path.join(BASE_DIR, 'data', 'train')
test_data_dir = os.path.join(BASE_DIR, 'data', 'test')

# List of CSV files
csv_files = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
]

# Create the directories if they don't exist
for directory in [normalized_data_dir, train_data_dir, test_data_dir]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Function to normalize the data
def normalize_data(df):
    scaler = StandardScaler()
    
    # Separate features and label
    features = df.drop(columns=['Label'])
    label = df['Label']
    
    # Replace infinity values with NaN
    features.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Fill NaN values with the mean of the column
    features.fillna(features.mean(), inplace=True)
    
    # Normalize the features
    features_scaled = pd.DataFrame(scaler.fit_transform(features), columns=features.columns)
    
    # Combine normalized features and label
    df_scaled = pd.concat([features_scaled, label], axis=1)
    
    return df_scaled

# Function to perform feature engineering
def feature_engineering(df):
    # Interaction features
    df['Flow Bytes/s * Flow Duration'] = df['Flow Bytes/s'] * df['Flow Duration']
    df['Total Length of Fwd Packets * Total Length of Bwd Packets'] = df['Total Length of Fwd Packets'] * df['Total Length of Bwd Packets']
    df['Fwd Packets/s * Bwd Packets/s'] = df['Fwd Packets/s'] * df['Bwd Packets/s']

    # Polynomial features
    df['Flow Duration^2'] = df['Flow Duration'] ** 2
    df['Flow Duration^3'] = df['Flow Duration'] ** 3

    # Statistical aggregations
    df['Mean Packet Length'] = df[['Fwd Packet Length Mean', 'Bwd Packet Length Mean']].mean(axis=1)
    df['Std Packet Length'] = df[['Fwd Packet Length Std', 'Bwd Packet Length Std']].std(axis=1)
    df['Max Packet Length'] = df[['Fwd Packet Length Max', 'Bwd Packet Length Max']].max(axis=1)
    df['Min Packet Length'] = df[['Fwd Packet Length Min', 'Bwd Packet Length Min']].min(axis=1)

    # Domain-specific features
    df['Flow Duration / Total Fwd Packets'] = df['Flow Duration'] / (df['Total Fwd Packets'] + 1)
    df['Flow Duration / Total Backward Packets'] = df['Flow Duration'] / (df['Total Backward Packets'] + 1)
    df['Total Fwd Packets / Total Backward Packets'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
    df['Fwd Packets/s / Bwd Packets/s'] = df['Fwd Packets/s'] / (df['Bwd Packets/s'] + 1)
    df['Flow Bytes/s / Flow Packets/s'] = df['Flow Bytes/s'] / (df['Flow Packets/s'] + 1)
    
    return df

# Function to split data into training and testing sets
def split_data(df, test_size=0.2, random_state=42):
    # Separate features and label
    features = df.drop(columns=['Label'])
    label = df['Label']
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(features, label, test_size=test_size, random_state=random_state)
    
    # Combine features and label for train and test sets
    train_df = pd.concat([X_train, y_train], axis=1)
    test_df = pd.concat([X_test, y_test], axis=1)
    
    return train_df, test_df

# Collect and process the data from each CSV file
for file_name in csv_files:
    file_path = os.path.join(cleaned_data_dir, file_name)
    df = pd.read_csv(file_path)
    
    # Ensure all 79 features are included
    features = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
        'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
        'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
        'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
        'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
        'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
        'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
        'Label'
    ]
    
    # Select only the necessary features
    df = df[features]
    
    # Perform feature engineering
    df = feature_engineering(df)
    
    # Normalize the data
    normalized_df = normalize_data(df)
    
    # Save the normalized data to a separate file in the normalized data directory
    normalized_file_path = os.path.join(normalized_data_dir, file_name)
    normalized_df.to_csv(normalized_file_path, index=False)
    
    # Split the data
    train_df, test_df = split_data(normalized_df)
    
    # Save the train and test data to separate files in the respective directories
    train_file_path = os.path.join(train_data_dir, file_name)
    test_file_path = os.path.join(test_data_dir, file_name)
    
    train_df.to_csv(train_file_path, index=False)
    test_df.to_csv(test_file_path, index=False)

    print(f"Data normalized, engineered, split, and saved to '{normalized_file_path}', '{train_file_path}', and '{test_file_path}'.")

print("Normalization, feature engineering, and data splitting complete.")
