#!/bin/bash
# ============================================
#  WGU D385 Task 2 - Stop Application
#  macOS Script
# ============================================

echo "============================================"
echo " Stopping Flask Application (port 5000)..."
echo "============================================"
echo ""

# Find and kill the process using port 5000
PID=$(lsof -ti :5000)

if [ -n "$PID" ]; then
    echo "Stopping process with PID: $PID"
    kill "$PID" 2>/dev/null
    sleep 1
    # Force kill if still running
    if kill -0 "$PID" 2>/dev/null; then
        kill -9 "$PID" 2>/dev/null
    fi
    echo ""
    echo "Application stopped."
else
    echo "No application found running on port 5000."
fi
