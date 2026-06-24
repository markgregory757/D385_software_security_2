@echo off
REM ============================================
REM  WGU D385 Task 2 - Stop Application
REM  Windows Script
REM ============================================

echo ============================================
echo  Stopping Flask Application (port 5000)...
echo ============================================
echo.

REM Find and kill the process using port 5000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
    echo Stopping process with PID: %%a
    taskkill /PID %%a /F >nul 2>nul
)

REM Also kill any python processes running app_student.py
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *app_student*" >nul 2>nul

echo.
echo Application stopped.
pause
