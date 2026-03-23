import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# -------------------- CONFIGURATION --------------------
# Use relative paths for portability
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_FOLDER = os.path.join(BASE_DIR, 'data', 'train')
TEST_FOLDER  = os.path.join(BASE_DIR, 'data', 'test')
MODEL_SAVE_DIR = os.path.join(BASE_DIR, 'models')
EVAL_SAVE_PATH = os.path.join(BASE_DIR, 'evaluation_results', 'gradient_boosting_evaluation.csv')

# List of all columns as provided (last two: 'Label', 'Protocol')
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

# For model features, use all columns except 'Label' and 'Protocol'
features_input = all_features[:-2]
label_column = 'Label'

# Allowed labels for this project:
allowed_labels = ["BENIGN", "DDoS", "PortScan", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

# -------------------- DATA LOADING FUNCTION --------------------
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
            # Keep only allowed labels
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

# -------------------- LABEL ENCODING --------------------
le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc = le.transform(y_test)
print("Classes:", le.classes_)

# -------------------- DATA NORMALIZATION --------------------
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# -------------------- GRADIENT BOOSTING MODEL (XGBoost) DEFINITION --------------------
import xgboost as xgb

# Define the XGBoost classifier with fine-tuned hyperparameters.
# These hyperparameters are chosen as an example; further tuning may be required.
gbc = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softmax',  # Multiclass classification
    num_class=len(allowed_labels),
    random_state=42,
    verbosity=1,
    use_label_encoder=False
)

# -------------------- MODEL TRAINING --------------------
print("Training Gradient Boosting model (XGBoost)...")
gbc.fit(X_train_scaled, y_train_enc)
gbc_model_path = os.path.join(MODEL_SAVE_DIR, "gradient_boosting_model.joblib")
joblib.dump(gbc, gbc_model_path)
print(f"Gradient Boosting model saved at: {gbc_model_path}")

# -------------------- EVALUATION --------------------
y_pred = gbc.predict(X_test_scaled)
overall_accuracy = accuracy_score(y_test_enc, y_pred)
print(f"Overall Test Accuracy: {overall_accuracy:.4f}")

evaluation_results = []
for i, label in enumerate(le.classes_):
    y_true_binary = (y_test_enc == i).astype(int)
    y_pred_binary = (y_pred == i).astype(int)
    
    acc = accuracy_score(y_true_binary, y_pred_binary)
    prec = precision_score(y_true_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_true_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
    if len(np.unique(y_true_binary)) > 1:
        auc = roc_auc_score(y_true_binary, (y_pred_binary).astype(float))
    else:
        auc = np.nan
        
    evaluation_results.append([label, acc, prec, rec, f1, auc])
    print(f"Evaluated {label}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc}")

eval_df = pd.DataFrame(evaluation_results, columns=["Label", "Accuracy", "Precision", "Recall", "F1-Score", "AUC"])
os.makedirs(os.path.dirname(EVAL_SAVE_PATH), exist_ok=True)
eval_df.to_csv(EVAL_SAVE_PATH, index=False)
print(f"Evaluation complete. Results saved at: {EVAL_SAVE_PATH}")
