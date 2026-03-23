import os
import numpy as np
np.bool = np.bool_
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Conv1D, MaxPooling1D, BatchNormalization, Activation, GlobalAveragePooling1D, Dense, Dropout, Flatten
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# -------------------- CONFIGURATION --------------------
# Use relative paths for portability
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_FOLDER = os.path.join(BASE_DIR, 'data', 'train')
TEST_FOLDER  = os.path.join(BASE_DIR, 'data', 'test')
MODEL_SAVE_DIR = os.path.join(BASE_DIR, 'models')
EVAL_SAVE_PATH = os.path.join(BASE_DIR, 'evaluation_results', 'cnn_evaluation.csv')

# Full list of columns as provided (last two columns: 'Label', 'Protocol')
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

# For CNN input, use all columns except 'Label' and 'Protocol'
features_input = all_features[:-2]
label_column = 'Label'

# Allowed labels for CNN classification
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
            # Filter rows to allowed labels only
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
num_classes = len(le.classes_)
print("Classes:", le.classes_)

# Convert labels to one-hot encoding for CNN training
y_train_onehot = keras.utils.to_categorical(y_train_enc, num_classes=num_classes)
y_test_onehot = keras.utils.to_categorical(y_test_enc, num_classes=num_classes)

# -------------------- DATA NORMALIZATION --------------------
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# -------------------- RESHAPE DATA FOR CNN --------------------
# Reshape data from (samples, features) to (samples, features, 1) for 1D CNN
X_train_cnn = np.expand_dims(X_train_scaled, axis=-1)
X_test_cnn = np.expand_dims(X_test_scaled, axis=-1)

# -------------------- CNN MODEL DEFINITION --------------------
def build_cnn_model(input_shape, num_classes):
    inputs = Input(shape=input_shape)
    
    # First Convolutional Block
    x = Conv1D(filters=64, kernel_size=3, activation='relu', padding='same')(inputs)
    x = BatchNormalization()(x)
    x = MaxPooling1D(pool_size=2)(x)
    
    # Second Convolutional Block
    x = Conv1D(filters=128, kernel_size=3, activation='relu', padding='same')(x)
    x = BatchNormalization()(x)
    x = MaxPooling1D(pool_size=2)(x)
    
    # Third Convolutional Block
    x = Conv1D(filters=256, kernel_size=3, activation='relu', padding='same')(x)
    x = BatchNormalization()(x)
    x = MaxPooling1D(pool_size=2)(x)
    
    # Global Average Pooling to reduce dimensions
    x = GlobalAveragePooling1D()(x)
    
    # Dense layers for classification
    x = Dense(128, activation='relu')(x)
    x = Dropout(0.5)(x)
    outputs = Dense(num_classes, activation='softmax')(x)
    
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

input_shape = X_train_cnn.shape[1:]  # (n_features, 1)
cnn_model = build_cnn_model(input_shape, num_classes)
cnn_model.summary()

# -------------------- MODEL TRAINING --------------------
cnn_history = cnn_model.fit(
    X_train_cnn, y_train_onehot,
    epochs=50,
    batch_size=256,
    validation_data=(X_test_cnn, y_test_onehot),
    verbose=2
)

# Save CNN model in native Keras format
cnn_model_path = os.path.join(MODEL_SAVE_DIR, "cnn_model.keras")
cnn_model.save(cnn_model_path)
print(f"CNN model training complete. Model saved at: {cnn_model_path}")

# -------------------- EVALUATION --------------------
# Predict probabilities and class labels on test data
y_pred_prob = cnn_model.predict(X_test_cnn)
y_pred = np.argmax(y_pred_prob, axis=1)

overall_accuracy = accuracy_score(y_test_enc, y_pred)
print(f"Overall Test Accuracy: {overall_accuracy:.4f}")

# Per-class evaluation metrics
evaluation_results = []
for i, label in enumerate(le.classes_):
    # Create binary labels for the current class (1 if current class, else 0)
    y_true_binary = (y_test_enc == i).astype(int)
    y_pred_binary = (y_pred == i).astype(int)
    
    acc = accuracy_score(y_true_binary, y_pred_binary)
    prec = precision_score(y_true_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_true_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
    if len(np.unique(y_true_binary)) > 1:
        auc = roc_auc_score(y_true_binary, y_pred_prob[:, i])
    else:
        auc = np.nan
    
    evaluation_results.append([label, acc, prec, rec, f1, auc])
    print(f"Evaluated {label}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc}")
    
# Save evaluation results to CSV
eval_df = pd.DataFrame(evaluation_results, columns=["Label", "Accuracy", "Precision", "Recall", "F1-Score", "AUC"])
os.makedirs(os.path.dirname(EVAL_SAVE_PATH), exist_ok=True)
eval_df.to_csv(EVAL_SAVE_PATH, index=False)
print(f"Evaluation complete. Results saved at: {EVAL_SAVE_PATH}")
