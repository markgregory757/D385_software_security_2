#!/bin/bash
# ============================================
#  WGU D385 Task 2 - Start Application
#  macOS Script
# ============================================

echo "============================================"
echo " WGU Construction Equipment Rental API"
echo " Starting Application..."
echo "============================================"
echo ""

# Navigate to the script's directory
cd "$(dirname "$0")"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed."
    echo "Please install Python from https://www.python.org/downloads/"
    exit 1
fi

# Install dependencies if needed
echo "Installing dependencies..."
pip3 install -r requirements.txt --quiet
echo ""

# Start the Flask application
echo "Starting Flask server on http://localhost:5000"
echo "Press Ctrl+C to stop the server."
echo ""
python3 app_student.py
