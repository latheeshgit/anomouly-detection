import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# -------------------- CONFIGURATION --------------------

TRAIN_FOLDER = r"E:\CloudAnomalyDetectionSystem\data\train"
TEST_FOLDER  = r"E:\CloudAnomalyDetectionSystem\data\test"
MODEL_SAVE_DIR = r"E:\CloudAnomalyDetectionSystem\models"
EVAL_SAVE_PATH = r"E:\CloudAnomalyDetectionSystem\results\evaluation_metrics\combined_autoencoder_evaluation.csv"

# All columns from the dataset (last two are 'Label' and 'Protocol')
all_features = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min', 'Flow Bytes/s * Flow Duration',
    'Total Length of Fwd Packets * Total Length of Bwd Packets',
    'Fwd Packets/s * Bwd Packets/s', 'Flow Duration^2', 'Flow Duration^3',
    'Mean Packet Length', 'Std Packet Length',
    'Flow Duration / Total Fwd Packets',
    'Flow Duration / Total Backward Packets',
    'Total Fwd Packets / Total Backward Packets',
    'Fwd Packets/s / Bwd Packets/s', 'Flow Bytes/s / Flow Packets/s',
    'Label', 'Protocol'
]

# For training input, use all columns except the last two ('Label', 'Protocol')
features_input = all_features[:-2]
label_column = 'Label'

# Allowed labels (we exclude some rare or unwanted ones)
allowed_labels = ["BENIGN", "DDoS", "PortScan", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

# -------------------- DATA LOADING --------------------

def load_data_from_folder(folder_path):
    X_list = []
    y_list = []
    for file in os.listdir(folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(folder_path, file)
            try:
                df = pd.read_csv(file_path, usecols=features_input + [label_column])
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.dropna(inplace=True)
            # Filter rows to allowed labels
            df = df[df[label_column].isin(allowed_labels)]
            if df.empty:
                continue
            X_list.append(df[features_input].values)
            y_list.append(df[label_column].values)
    if not X_list:
        raise FileNotFoundError(f"No CSV files found in {folder_path} with allowed labels.")
    X = np.vstack(X_list)
    y = np.concatenate(y_list)
    return X, y

print("Loading training data...")
X_train_full, y_train_full = load_data_from_folder(TRAIN_FOLDER)
print("Loading test data...")
X_test, y_test = load_data_from_folder(TEST_FOLDER)

# -------------------- SEPARATE DATA FOR BENIGN AND ANOMALIES --------------------

# Split training data into BENIGN and anomalies (all anomalies combined)
benign_indices = np.where(y_train_full == "BENIGN")[0]
anomaly_indices = np.where(y_train_full != "BENIGN")[0]

print(f"Original training data: BENIGN = {len(benign_indices)}, Anomaly = {len(anomaly_indices)}")

X_train_benign = X_train_full[benign_indices]
y_train_benign = y_train_full[benign_indices]

X_train_anomaly = X_train_full[anomaly_indices]
y_train_anomaly = y_train_full[anomaly_indices]

# Optionally, you can undersample BENIGN if desired for balance.
# For this example, we use all anomaly samples and undersample BENIGN to the same number:
if len(X_train_benign) > len(X_train_anomaly):
    np.random.seed(42)
    selected_benign_indices = np.random.choice(len(X_train_benign), size=len(X_train_anomaly), replace=False)
    X_train_benign = X_train_benign[selected_benign_indices]
    y_train_benign = y_train_benign[selected_benign_indices]

print(f"Balanced training data: BENIGN = {len(X_train_benign)}, Anomaly = {len(X_train_anomaly)}")

# -------------------- NORMALIZATION --------------------
# Fit a common scaler on the combined training data for consistency
combined_train = np.vstack([X_train_benign, X_train_anomaly])
scaler = MinMaxScaler()
scaler.fit(combined_train)

X_train_benign_scaled = scaler.transform(X_train_benign)
X_train_anomaly_scaled = scaler.transform(X_train_anomaly)
X_test_scaled = scaler.transform(X_test)

# -------------------- AUTOENCODER MODEL DEFINITION --------------------

def build_autoencoder(input_dim):
    input_layer = Input(shape=(input_dim,))
    # Encoder
    encoded = Dense(128, activation='relu')(input_layer)
    encoded = Dense(64, activation='relu')(encoded)
    encoded = Dense(32, activation='relu')(encoded)
    latent = Dense(16, activation='relu')(encoded)
    # Decoder
    decoded = Dense(32, activation='relu')(latent)
    decoded = Dense(64, activation='relu')(decoded)
    decoded = Dense(128, activation='relu')(decoded)
    output_layer = Dense(input_dim, activation='sigmoid')(decoded)
    
    autoencoder = Model(inputs=input_layer, outputs=output_layer)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

input_dim = X_train_benign_scaled.shape[1]

# -------------------- TRAIN AUTOENCODER FOR BENIGN --------------------
print("Training autoencoder for BENIGN data...")
autoencoder_benign = build_autoencoder(input_dim)
autoencoder_benign.fit(X_train_benign_scaled, X_train_benign_scaled, epochs=50, batch_size=256, shuffle=True, verbose=2)
benign_model_path = os.path.join(MODEL_SAVE_DIR, "autoencoder_BENIGN.keras")
autoencoder_benign.save(benign_model_path)
print(f"BENIGN model saved at: {benign_model_path}")

# -------------------- TRAIN AUTOENCODER FOR ANOMALIES (combined) --------------------
print("Training autoencoder for anomaly data (combined)...")
autoencoder_anomaly = build_autoencoder(input_dim)
autoencoder_anomaly.fit(X_train_anomaly_scaled, X_train_anomaly_scaled, epochs=50, batch_size=256, shuffle=True, verbose=2)
anomaly_model_path = os.path.join(MODEL_SAVE_DIR, "autoencoder_Anomaly.keras")
autoencoder_anomaly.save(anomaly_model_path)
print(f"Anomaly model saved at: {anomaly_model_path}")

# -------------------- COMBINED EVALUATION --------------------
# For each test sample, we compute reconstruction error from both models.
def reconstruction_error(model, X):
    reconstructions = model.predict(X)
    return np.mean(np.square(X - reconstructions), axis=1)

errors_benign = reconstruction_error(autoencoder_benign, X_test_scaled)
errors_anomaly = reconstruction_error(autoencoder_anomaly, X_test_scaled)

# Combined decision: For each sample, if benign model error < anomaly model error, classify as BENIGN; otherwise, classify as anomaly.
predicted_labels = []
for i in range(X_test_scaled.shape[0]):
    if errors_benign[i] < errors_anomaly[i]:
        predicted_labels.append("BENIGN")
    else:
        # If not benign, we classify it as an anomaly.
        # Since the anomaly autoencoder is trained on combined anomalies, we label it generically as 'Anomaly'
        predicted_labels.append("Anomaly")
predicted_labels = np.array(predicted_labels)

# Create binary ground truth for overall evaluation: BENIGN = 0, Anomaly = 1
y_test_binary = np.where(y_test == "BENIGN", 0, 1)
y_pred_binary = np.where(predicted_labels == "BENIGN", 0, 1)

overall_acc = accuracy_score(y_test_binary, y_pred_binary)
overall_prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
overall_rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)
overall_f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
if len(np.unique(y_test_binary)) > 1:
    overall_auc = roc_auc_score(y_test_binary, errors_anomaly - errors_benign)
else:
    overall_auc = np.nan

print(f"Overall Evaluation: Accuracy={overall_acc:.4f}, Precision={overall_prec:.4f}, Recall={overall_rec:.4f}, F1-Score={overall_f1:.4f}, AUC={overall_auc}")

# Additionally, evaluate per label for anomalies only (for BENIGN we already have overall)
evaluation_results = []
for label in allowed_labels:
    # For BENIGN, we use binary labels directly; for anomalies, we check if the true label equals that anomaly.
    if label == "BENIGN":
        y_true = np.where(y_test == "BENIGN", 1, 0)  # 1 if benign, 0 otherwise
        y_pred = np.where(predicted_labels == "BENIGN", 1, 0)
    else:
        y_true = np.where(y_test == label, 1, 0)
        y_pred = np.where((y_test != "BENIGN") & (predicted_labels == "Anomaly"), 1, 0)
    if len(np.unique(y_true)) > 1:
        auc = roc_auc_score(y_true, errors_anomaly - errors_benign)
    else:
        auc = np.nan
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    evaluation_results.append([label, acc, prec, rec, f1, auc])
    print(f"Evaluated {label}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc}")

# Save evaluation results
eval_df = pd.DataFrame(evaluation_results, columns=["Label", "Accuracy", "Precision", "Recall", "F1-Score", "AUC"])
os.makedirs(os.path.dirname(EVAL_SAVE_PATH), exist_ok=True)
eval_df.to_csv(EVAL_SAVE_PATH, index=False)
print(f"Combined evaluation complete. Results saved at: {EVAL_SAVE_PATH}")
