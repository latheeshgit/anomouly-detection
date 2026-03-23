-- Create the database
CREATE DATABASE IF NOT EXISTS cloud_anomaly_db;

-- Use the database
USE cloud_anomaly_db;

-- Create the uploads table
CREATE TABLE IF NOT EXISTS uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_names TEXT NOT NULL,
    file_types TEXT NOT NULL,
    detection_status VARCHAR(255) NOT NULL,
    timestamp DATETIME NOT NULL
);

-- Optional: Create a user and grant privileges if needed
-- CREATE USER 'anomaly_user'@'localhost' IDENTIFIED BY 'your_password';
-- GRANT ALL PRIVILEGES ON cloud_anomaly_db.* TO 'anomaly_user'@'localhost';
-- FLUSH PRIVILEGES;
