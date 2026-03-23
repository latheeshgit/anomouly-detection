@echo off
SETLOCAL

:: Configuration
SET VENV_DIR=venv
SET REQUIREMENTS=requirements.txt
SET APP_SCRIPT=app\app.py

echo === Cloud Network Anomaly Detection System Launcher ===

:: 1. Check Python Installation
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Python is not installed or not in your PATH.
    echo Please install Python 3.8+ from python.org and try again.
    pause
    exit /b 1
)

:: 2. Check/Create Virtual Environment
IF NOT EXIST "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
    IF %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to create virtual environment.
        pause
        exit /b 1
    )
    
    echo Installing dependencies...
    "%VENV_DIR%\Scripts\pip" install -r %REQUIREMENTS%
) ELSE (
    echo Virtual environment found.
)

:: 3. Check for Dummy Attack Script
IF NOT EXIST "DDoS.py" (
    echo Creating test attack script (DDoS.py)...
    echo import time; print("Simulating DDoS Attack..."); time.sleep(60) > DDoS.py
)

:: 4. Start the Application
echo Starting Application...
echo Open your browser to: http://127.0.0.1:8080
"%VENV_DIR%\Scripts\python" %APP_SCRIPT%

pause
