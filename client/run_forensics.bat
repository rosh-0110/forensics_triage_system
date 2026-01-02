@echo off
echo ========================================
echo   FORENSIC EVIDENCE COLLECTION TOOL
echo ========================================
echo.
echo Starting evidence collection...
echo.
cd /d C:\forensics_project\client
python collector.py
echo.
echo ========================================
echo Collection complete!
echo Opening dashboard in browser...
echo ========================================
timeout /t 3 /nobreak >nul
start https://192.168.56.20:5000
echo.
echo Press any key to close this window...
pause >nul