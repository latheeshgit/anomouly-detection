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

# -------------- CONFIGURATION --------------

# Paths to training and test folders
TRAIN_FOLDER = r"E:\CloudAnomalyDetectionSystem\data\train"
TEST_FOLDER  = r"E:\CloudAnomalyDetectionSystem\data\test"
# Path to save the model (using native Keras format)
MODEL_SAVE_PATH = r"E:\CloudAnomalyDetectionSystem\models\autoencoder_model.keras"
# Path to save evaluation results
EVAL_SAVE_PATH = r"E:\CloudAnomalyDetectionSystem\results\evaluation_metrics\autoencoder_evaluation.csv"

# List of all columns from the dataset (as provided)
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

# For model training, use all columns except 'Label' and 'Protocol'
features_input = all_features[:-2]
# We'll keep the 'Label' column for evaluation
label_column = 'Label'

# Define allowed labels for evaluation (only these will be used)
allowed_labels = ["BENIGN", "DDoS", "PortScan", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

# -------------- DATA LOADING FUNCTIONS --------------

def load_data_from_folder(folder_path):
    X_list = []
    y_list = []
    # Process each CSV file in the directory
    for file in os.listdir(folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(folder_path, file)
            df = pd.read_csv(file_path, usecols=features_input + [label_column])
            # Replace infinities and drop NaN values
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.dropna(inplace=True)
            # Filter to allowed labels only
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
X_train, y_train = load_data_from_folder(TRAIN_FOLDER)
print("Loading test data...")
X_test, y_test = load_data_from_folder(TEST_FOLDER)

# -------------- BALANCE THE TRAINING DATA --------------
# Separate BENIGN and anomaly samples in training set
benign_indices = np.where(y_train == "BENIGN")[0]
anomaly_indices = np.where(y_train != "BENIGN")[0]

print(f"Original training data: BENIGN = {len(benign_indices)}, Anomaly = {len(anomaly_indices)}")

# Undersample BENIGN to match the number of anomaly samples
if len(benign_indices) > len(anomaly_indices):
    np.random.seed(42)
    benign_indices = np.random.choice(benign_indices, size=len(anomaly_indices), replace=False)

selected_indices = np.concatenate([benign_indices, anomaly_indices])
X_train_balanced = X_train[selected_indices]
y_train_balanced = y_train[selected_indices]

print(f"Balanced training data: {len(y_train_balanced)} samples")

# -------------- DATA NORMALIZATION --------------
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train_balanced)
X_test_scaled = scaler.transform(X_test)

# -------------- AUTOENCODER MODEL DEFINITION --------------

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

input_dim = X_train_scaled.shape[1]
autoencoder = build_autoencoder(input_dim)
autoencoder.summary()

# -------------- MODEL TRAINING --------------

history = autoencoder.fit(
    X_train_scaled, X_train_scaled,
    epochs=50,
    batch_size=256,
    shuffle=True,
    validation_data=(X_test_scaled, X_test_scaled),
    verbose=2
)

# Save model using native Keras format
autoencoder.save(MODEL_SAVE_PATH)
print(f"Autoencoder model training complete. Model saved at: {MODEL_SAVE_PATH}")

# -------------- EVALUATION --------------

def evaluate_autoencoder(model, X):
    reconstructions = model.predict(X)
    errors = np.mean(np.square(X - reconstructions), axis=1)
    return errors

# Compute reconstruction errors on test set
errors_test = evaluate_autoencoder(autoencoder, X_test_scaled)

# Set threshold based on the 95th percentile error for BENIGN samples in test set
benign_errors = errors_test[y_test == "BENIGN"]
if len(benign_errors) == 0:
    raise ValueError("No BENIGN samples found in test data to set threshold.")
threshold = np.percentile(benign_errors, 95)
print(f"Anomaly detection threshold (95th percentile of BENIGN errors): {threshold}")

# Generate binary predictions (using the threshold)
# Note: Here, predictions are 0 for samples with error <= threshold (classified as BENIGN),
# and 1 for samples with error > threshold (classified as anomaly).
predictions = (errors_test > threshold).astype(int)

# Evaluate metrics for each allowed label separately
evaluation_results = []
for label in allowed_labels:
    # For each label, treat samples of that label as positive (1), others as negative (0)
    y_binary = np.where(y_test == label, 1, 0)
    if len(np.unique(y_binary)) > 1:
        auc = roc_auc_score(y_binary, errors_test)
    else:
        auc = np.nan
    acc = accuracy_score(y_binary, predictions)
    prec = precision_score(y_binary, predictions, zero_division=0)
    rec = recall_score(y_binary, predictions, zero_division=0)
    f1 = f1_score(y_binary, predictions, zero_division=0)
    evaluation_results.append([label, acc, prec, rec, f1, auc])
    print(f"Evaluated {label}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc}")

# Save evaluation results to CSV
eval_df = pd.DataFrame(evaluation_results, columns=["Attack Type", "Accuracy", "Precision", "Recall", "F1-Score", "AUC"])
os.makedirs(os.path.dirname(EVAL_SAVE_PATH), exist_ok=True)
eval_df.to_csv(EVAL_SAVE_PATH, index=False)
print(f"Evaluation complete. Results saved at: {EVAL_SAVE_PATH}")
