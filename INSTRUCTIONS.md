# Google Cloud Platform & Drive API Setup Guide

This project requires a Google Drive API integration to store uploaded files.

## 1. Google Cloud Console Setup
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project named `CloudAnomalyDetection`.
3. Enable the **Google Drive API**:
   - Go to **APIs & Services > Library**.
   - Search for "Google Drive API" and click **Enable**.
4. Create a **Service Account**:
   - Go to **APIs & Services > Credentials**.
   - Click **Create Credentials > Service Account**.
   - Give it a name (e.g., `drive-uploader`) and click **Create and Continue**.
   - (Optional) Grant it the "Editor" role for the project.
5. Generate a **JSON Key**:
   - After creating the service account, click on it in the list.
   - Go to the **Keys** tab.
   - Click **Add Key > Create new key**.
   - Select **JSON** and click **Create**.
   - Download the file and rename it to `service_account.json`.
   - **Important**: Place this file in the `app/` directory of this project.

## 2. Shared Folder (Optional)
If you want to see the files in your personal Google Drive:
1. Open the `service_account.json` file and find the `client_email` address.
2. Go to your Google Drive and create a folder named `Files`.
3. Share that folder with the `client_email` address you found.

## 3. Environment Setup
Run the following commands to install dependencies:
```bash
pip install -r requirements.txt
```

## 4. Database Setup
Ensure you have MySQL installed locally. Run the provided `setup_db.sql` script:
```bash
mysql -u root -p < setup_db.sql
```

## 5. Running the Application
1. Generate mock data (if you don't have the real dataset):
   ```bash
   python generate_mock_data.py
   ```
2. Run the cleanup and training scripts (optional, if you want to retrain):
   ```bash
   python scripts/data_clean_process.py
   python scripts/train_test.py
   python scripts/cnn.py
   ```
3. Start the Flask app:
   ```bash
   python app/app.py
   ```
