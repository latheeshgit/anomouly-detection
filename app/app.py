import os
import sys
import time
import threading
import tempfile
import psutil
import mysql.connector
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import tensorflow as tf
from tensorflow import keras
import joblib

app = Flask(__name__)
# Use relative paths for portability
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_dir = os.path.join(BASE_DIR, 'models')

# Load Keras models (with .keras extension)
# Note: Check if these files exist before loading to prevent startup crash
def load_keras_model(name):
    path = os.path.join(model_dir, name)
    if os.path.exists(path):
        return keras.models.load_model(path)
    print(f"Warning: Model not found at {path}")
    return None

autoencoder_anomaly = load_keras_model('autoencoder_Anomaly.keras')
autoencoder_benign = load_keras_model('autoencoder_BENIGN.keras')
cnn_model = load_keras_model('cnn_model.keras')
vgg16_model = load_keras_model('VGG-16.keras')

# Load joblib model
gb_path = os.path.join(model_dir, 'gradient_boosting_model.joblib')
gradient_boosting = joblib.load(gb_path) if os.path.exists(gb_path) else None

print("All models loaded successfully!")

# Allowed file extensions and max file size (1GB)
ALLOWED_EXTENSIONS = {
    '.mp3', '.wav', '.mp4', '.avi', '.jpg', '.jpeg',
    '.png', '.pdf', '.docx', '.zip', '.json', '.html'
}
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB

# Update with your service account credentials file path
SERVICE_ACCOUNT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'service_account.json')

ATTACK_SCRIPTS = [
    "DDoS.py", "PortScan.py", "DoS_Hulk.py", "DoS_GoldenEye.py",
    "DoS_slowloris.py", "DoS_Slowhttptest.py"
]
upload_progress = {}  # Dictionary to store progress for each upload_id

# Global variable to capture the anomaly type (script name without .py)
detected_script = None
# ------------------ Utility Functions ------------------
def is_allowed_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    return ext in ALLOWED_EXTENSIONS


# ------------- Database Configuration -------------
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', '27072004'),
    'database': os.environ.get('DB_NAME', 'cloud_anomaly_db')
}

# ------------- MySQL Database Update Function -------------
def update_database(file_names, file_types, detection_status, timestamp):
    """
    Inserts a record into the MySQL database.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        sql = "INSERT INTO uploads (file_names, file_types, detection_status, timestamp) VALUES (%s, %s, %s, %s)"
        values = (file_names, file_types, detection_status, timestamp)
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        print("Record inserted successfully into MySQL table")
    except Exception as e:
        print("Error while inserting record into MySQL:", e)

# ------------- MySQL Database Fetch Function -------------
def fetch_uploads():
    """
    Retrieves all records from the uploads table.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM uploads ORDER BY timestamp DESC")
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return results
    except Exception as e:
        print("Error while fetching records from MySQL:", e)
        return []

# ------------- Google Drive Service Functions -------------
import google.auth

def build_drive_service():
    SCOPES = ['https://www.googleapis.com/auth/drive']
    
    # Try using the JSON key file first
    if os.path.exists(SERVICE_ACCOUNT_FILE):
        print(f"Using service account key from: {SERVICE_ACCOUNT_FILE}")
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES
        )
    else:
        # Fallback to Application Default Credentials (ADC)
        print("No JSON key found. Falling back to Application Default Credentials...")
        try:
            credentials, project = google.auth.default(scopes=SCOPES)
        except Exception as e:
            print(f"Error loading credentials: {e}")
            raise Exception("No valid Google Cloud credentials found. Please run 'gcloud auth application-default login'")
            
    return build('drive', 'v3', credentials=credentials)

def get_or_create_folder(drive_service, folder_name="Files"):
    query = (
        f"name='{folder_name}' and "
        "mimeType='application/vnd.google-apps.folder' and "
        "trashed=false"
    )
    results = drive_service.files().list(
        q=query, spaces='drive', fields="files(id, name)", pageSize=1
    ).execute()
    items = results.get('files', [])
    if items:
        folder_id = items[0]['id']
        print(f"Found folder '{folder_name}' with ID: {folder_id}")
        return folder_id
    else:
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        folder = drive_service.files().create(
            body=file_metadata, fields='id'
        ).execute()
        folder_id = folder.get('id')
        print(f"Created folder '{folder_name}' with ID: {folder_id}")
        return folder_id

def determine_chunk_size(file_size):
    if file_size < 10 * 1024 * 1024:  # < 10MB
        return 256 * 1024           # 256KB
    elif file_size < 100 * 1024 * 1024:  # < 100MB
        return 1 * 1024 * 1024         # 1MB
    else:
        return 5 * 1024 * 1024         # 5MB for files >= 100MB

# ------------- Modify the upload_file function to properly update progress ------------- 
def upload_file(file_path, drive_service, folder_id, update_callback, detect_event):
    if not is_allowed_file(file_path):
        update_callback(error="File format not allowed.", percent=0, speed=0)
        return None

    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        update_callback(error="File size exceeds 1GB limit.", percent=0, speed=0)
        return None

    file_name = os.path.basename(file_path)
    file_metadata = {'name': file_name, 'parents': [folder_id]}
    chunk_size = determine_chunk_size(file_size)
    media = MediaFileUpload(file_path, resumable=True, chunksize=chunk_size)
    request = drive_service.files().create(body=file_metadata, media_body=media, fields='id')

    prev_progress = 0.0
    response = None

    try:
        while response is None:
            if detect_event.is_set():
                raise Exception("Anomaly detected during file transfer")
            start_time = time.time()
            status, response = request.next_chunk()  # Blocks until next chunk finishes.
            end_time = time.time()
            if status:
                curr_progress = status.progress()  # value between 0 and 1
                delta = curr_progress - prev_progress
                bytes_uploaded = delta * file_size
                time_taken = end_time - start_time
                speed = (bytes_uploaded / time_taken) / 1024 if time_taken > 0 else 0
                percent = curr_progress * 100
                update_callback(percent=percent, speed=speed)
                prev_progress = curr_progress

        file_id = response.get('id')
        print(f"File '{file_name}' uploaded successfully with ID: {file_id}")
        return file_id
    except Exception as e:
        update_callback(error=str(e), percent=0, speed=0)
        print(f"Error uploading file '{file_name}': {e}")
        return None


# ------------- Anomaly Detection Function -------------
def detect_attack(detect_event, callback=None):
    """
    Continuously checks for running processes with suspicious script names.
    When a match is found, sets detect_event and (if provided) calls callback with the anomaly type.
    """
    global detected_script
    while not detect_event.is_set():
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline:
                    for script in ATTACK_SCRIPTS:
                        if script in ' '.join(cmdline):
                            detected_script = os.path.splitext(script)[0]  # remove .py extension
                            print(f"Anomaly detected: {detected_script}")
                            detect_event.set()
                            if callback:
                                callback(f"Anomaly detected: {detected_script}")
                            return
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(0.1)

# ------------- Dummy Update Callback -------------
def update_callback(error=None, percent=0, speed=0):
    if error:
        print(f"Update: Error - {error}")
    else:
        print(f"Progress: {percent:.0f}% | Speed: {speed:.2f} KB/s")

# ------------- Sequential Upload Function (Backend Version) -------------
def sequential_upload_backend(file_paths, drive_service, folder_id, detect_event):
    """
    Processes the list of file paths sequentially.
    Returns a list of tuples: (file_name, file_id or error message)
    """
    results = []
    total_size = sum(os.path.getsize(fp) for fp in file_paths)
    if total_size == 0:
        return [("No valid files to upload.", None)]
    
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        result = upload_file(file_path, drive_service, folder_id, update_callback, detect_event)
        if result is None:
            results.append((file_name, "Error or cancelled"))
            if detect_event.is_set():
                break
        else:
            results.append((file_name, result))
    return results

# ------------- Flask Routes for Frontend Pages -------------
@app.route('/')
def index():
    return render_template('base.html')

@app.route('/file_transfer')
def file_transfer():
    allowed_extensions = list(ALLOWED_EXTENSIONS)
    return render_template('file_transfer.html', allowed_extensions=allowed_extensions, max_size=MAX_FILE_SIZE)

@app.route('/results')
def results():
    uploads = fetch_uploads()
    return render_template('results.html', uploads=uploads)

# ------------- Fix the upload route to properly update progress -------------
@app.route('/upload', methods=['POST'])
def upload():
    if 'files' not in request.files:
        return jsonify({"error": "No files part in the request"}), 400

    files = request.files.getlist('files')
    if not files or len(files) == 0:
        return jsonify({"error": "No files selected"}), 400
    
    # Get the upload_id from the request
    upload_id = request.form.get('upload_id')
    if not upload_id:
        return jsonify({"error": "No upload ID provided"}), 400
    
    # Initialize progress tracking for this upload
    upload_progress[upload_id] = {
        "status": "processing",
        "progress": 0,
        "speed": 0,
        "anomaly_detected": False,
        "detection_status": "success"
    }

    # Save files to a temporary directory
    temp_dir = tempfile.mkdtemp()
    saved_file_paths = []
    for file in files:
        filename = secure_filename(file.filename)
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)
        saved_file_paths.append(file_path)

    file_names = ", ".join([os.path.basename(fp) for fp in saved_file_paths])
    file_types = ", ".join(set([os.path.splitext(fp)[1].lower() for fp in saved_file_paths]))

    # Define a custom callback that updates our progress dict
    def progress_callback(error=None, percent=0, speed=0):
        if error:
            upload_progress[upload_id]["status"] = "error"
            upload_progress[upload_id]["message"] = error
        else:
            upload_progress[upload_id]["progress"] = percent
            upload_progress[upload_id]["speed"] = speed
            print(f"Updated progress: {percent:.1f}%, Speed: {speed:.2f} KB/s for upload {upload_id}")

    # Run the upload in a separate thread
    def upload_thread_func():
        try:
            drive_service = build_drive_service()
            folder_id = get_or_create_folder(drive_service, folder_name="Files")

            detect_event = threading.Event()
            
            def anomaly_callback(message):
                upload_progress[upload_id]["anomaly_detected"] = True
                upload_progress[upload_id]["detection_status"] = message
                print(f"Anomaly callback triggered: {message}")
            
            anomaly_thread = threading.Thread(
                target=detect_attack, 
                args=(detect_event, anomaly_callback), 
                daemon=True
            )
            anomaly_thread.start()

            # Use our custom progress callback
            for file_path in saved_file_paths:
                if detect_event.is_set():
                    break
                    
                result = upload_file(
                    file_path,
                    drive_service,
                    folder_id,
                    progress_callback,  # Use our custom callback
                    detect_event
                )
                
                if result is None and detect_event.is_set():
                    break

            detection_status = detected_script if detect_event.is_set() and detected_script else "success"
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            update_database(file_names, file_types, detection_status, ts)

            # Update progress to complete
            upload_progress[upload_id]["status"] = "complete"
            upload_progress[upload_id]["progress"] = 100  # Ensure 100% at completion
            upload_progress[upload_id]["detection_status"] = detection_status
            print(f"Upload {upload_id} completed with status: {detection_status}")
            
            # Clean up
            for fp in saved_file_paths:
                try:
                    os.remove(fp)
                except Exception as e:
                    print("Error removing temp file:", e)
            try:
                os.rmdir(temp_dir)
            except Exception as e:
                print("Error removing temp directory:", e)
                
            # Keep the progress data available for a while
            def cleanup_progress():
                time.sleep(300)  # 5 minutes
                if upload_id in upload_progress:
                    del upload_progress[upload_id]
                    
            cleanup_thread = threading.Thread(target=cleanup_progress, daemon=True)
            cleanup_thread.start()
                
        except Exception as e:
            upload_progress[upload_id]["status"] = "error"
            upload_progress[upload_id]["message"] = str(e)
            print(f"Error in upload thread: {e}")
    
    # Start the upload thread
    upload_thread = threading.Thread(target=upload_thread_func, daemon=True)
    upload_thread.start()
    
    # Return immediate response to let frontend know we've started processing
    return jsonify({
        "status": "processing",
        "message": "Upload started, check progress with the provided upload_id",
        "upload_id": upload_id
    })

# API endpoint to get real-time progress updates
@app.route('/api/progress', methods=['GET'])
def get_progress():
    upload_id = request.args.get('upload_id')
    if not upload_id or upload_id not in upload_progress:
        return jsonify({
            "status": "error",
            "message": "Invalid or expired upload ID"
        }), 404
    
    progress_data = upload_progress.get(upload_id, {})
    return jsonify(progress_data)

# ------------- Run the Flask App on 127.0.0.1:8080 -------------
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)