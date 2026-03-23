import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, BatchNormalization, Dropout
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# -------------------- CONFIGURATION --------------------
TRAIN_FOLDER = r"E:/CloudAnomalyDetectionSystem/data/train"
TEST_FOLDER  = r"E:/CloudAnomalyDetectionSystem/data/test"
MODEL_SAVE_DIR = r"E:/CloudAnomalyDetectionSystem/models"
EVAL_SAVE_PATH = r"E:/CloudAnomalyDetectionSystem/results/evaluation_metrics/vgg16_evaluation.csv"

# Full list of columns as provided (last two: 'Label', 'Protocol')
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

# For model input, use all columns except 'Label' and 'Protocol'
features_input = all_features[:-2]
label_column = 'Label'

# Allowed labels for classification
allowed_labels = ["BENIGN", "DDoS", "PortScan", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]

# -------------------- DATA LOADING FUNCTION --------------------
def load_data_from_folder(folder_path):
    X_list = []
    y_list = []
    for file in os.listdir(folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(folder_path, file)
            try:
                # Read only the necessary columns
                df = pd.read_csv(file_path, usecols=features_input + [label_column])
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue
            # Replace infinities and drop missing values
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.dropna(inplace=True)
            # Filter rows to only include allowed labels
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

# -------------------- DATA NORMALIZATION --------------------
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# -------------------- MODIFIED VGG-16 ARCHITECTURE FOR NUMERICAL DATA --------------------
def build_vgg16_numerical_model(input_shape, num_classes):
    inputs = Input(shape=(input_shape,))
    
    # Fully connected layers mimicking VGG-16 structure
    x = Dense(512, activation='relu')(inputs)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)

    x = Dense(1024, activation='relu')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)

    x = Dense(2048, activation='relu')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)

    x = Dense(1024, activation='relu')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)

    x = Dense(512, activation='relu')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)

    # Output layer for multi-class classification
    outputs = Dense(num_classes, activation='softmax')(x)

    model = Model(inputs, outputs)
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

input_shape_num = X_train_scaled.shape[1]
num_classes = len(le.classes_)

vgg16_numerical_model = build_vgg16_numerical_model(input_shape_num, num_classes)
vgg16_numerical_model.summary()

# -------------------- CONVERT LABELS TO ONE-HOT --------------------
y_train_onehot = keras.utils.to_categorical(y_train_enc, num_classes=num_classes)
y_test_onehot = keras.utils.to_categorical(y_test_enc, num_classes=num_classes)

# -------------------- MODEL TRAINING --------------------
vgg16_numerical_history = vgg16_numerical_model.fit(
    X_train_scaled, y_train_onehot,
    epochs=50,
    batch_size=256,
    validation_data=(X_test_scaled, y_test_onehot),
    verbose=2
)

# Ensure the model save directory exists before saving
os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
vgg16_numerical_model_path = os.path.join(MODEL_SAVE_DIR, "vgg16_numerical_model.keras")
vgg16_numerical_model.save(vgg16_numerical_model_path)
print(f"VGG-16 inspired numerical model training complete. Model saved at: {vgg16_numerical_model_path}")

# -------------------- EVALUATION --------------------
y_pred_prob = vgg16_numerical_model.predict(X_test_scaled)
y_pred = np.argmax(y_pred_prob, axis=1)
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
    # Calculate AUC only if both classes are present in y_true_binary
    if len(np.unique(y_true_binary)) > 1:
        auc = roc_auc_score(y_true_binary, y_pred_prob[:, i])
    else:
        auc = np.nan
    evaluation_results.append([label, acc, prec, rec, f1, auc])
    print(f"Evaluated {label}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc}")

eval_df = pd.DataFrame(evaluation_results, columns=["Label", "Accuracy", "Precision", "Recall", "F1-Score", "AUC"])
os.makedirs(os.path.dirname(EVAL_SAVE_PATH), exist_ok=True)
eval_df.to_csv(EVAL_SAVE_PATH, index=False)
print(f"Evaluation complete. Results saved at: {EVAL_SAVE_PATH}")
