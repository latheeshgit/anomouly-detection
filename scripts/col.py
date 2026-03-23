import os
import pandas as pd

# Define the directory where the raw data is stored using relative paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
normalized = os.path.join(BASE_DIR, 'data', 'normalized')
test = os.path.join(BASE_DIR, 'data', 'test')
train = os.path.join(BASE_DIR, 'data', 'train')


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

# Create the cleaned data directory if it doesn't exist
if not os.path.exists(train):
    os.makedirs(train)
if not os.path.exists(test):
    os.makedirs(test)
# Function to clean the data
def clean_data(df):
    # Handle missing values, remove irrelevant data, and correct inconsistencies
    # Example: Drop rows with any missing values
    df = df.dropna()
    return df

# Check the column names in the first CSV file
file_path = os.path.join(train, csv_files[0])
df = pd.read_csv(file_path)
print(df.columns)
file_p = os.path.join(test, csv_files[0])
df = pd.read_csv(file_p)
print(df.columns)

# Exit the script to avoid further errors
exit()
