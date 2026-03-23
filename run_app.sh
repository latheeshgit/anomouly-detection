#!/bin/bash

# Configuration
VENV_DIR="venv"
REQUIREMENTS="requirements.txt"
APP_SCRIPT="app/app.py"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Cloud Network Anomaly Detection System Launcher ===${NC}"

# 1. Check/Create Virtual Environment
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to create virtual environment. Do you have python3-venv installed?${NC}"
        echo "Try: sudo apt install python3-venv"
        exit 1
    fi
    
    echo -e "${GREEN}Installing dependencies...${NC}"
    ./"$VENV_DIR"/bin/pip install -r "$REQUIREMENTS"
else
    echo -e "${GREEN}Virtual environment found.${NC}"
fi

# 2. Check Database Connection (basic check)
# We won't force this, just a gentle reminder
echo -e "${GREEN}Checking Setup...${NC}"
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}Warning: MySQL is not installed. The app requires MySQL to store results.${NC}"
fi

# 3. Create Dummy Attack Script if missing (for testing)
if [ ! -f "DDoS.py" ]; then
    echo "Creating test attack script (DDoS.py)..."
    echo 'import time; print("Simulating DDoS Attack..."); time.sleep(60)' > DDoS.py
fi

# 4. Start the Application
echo -e "${GREEN}Starting Application...${NC}"
echo "Open your browser to: http://127.0.0.1:8080"
./"$VENV_DIR"/bin/python3 "$APP_SCRIPT"
