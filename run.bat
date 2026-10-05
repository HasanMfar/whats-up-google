@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install it from https://www.python.org/downloads/
  pause
  exit /b 1
)

python -c "import httpx, rich" >nul 2>nul || (
  echo Installing Python packages - one time only...
  python -m pip install -r requirements.txt
)

findstr /b /c:"http" subscriptions.txt >nul 2>nul || (
  echo Paste your subscription URLs in the file that opens - one per line - then save and close it.
  notepad subscriptions.txt
)

echo.
echo A menu will appear - choose 1 (Full scan) to test every config.
echo Press Ctrl+C at any time to stop; xray is closed along with the scanner.
echo.
python -m scanner

echo.
if exist best_subscription.txt (
  echo Done. Import best_subscription.txt into v2rayN - full report is in the reports folder.
) else (
  echo No importable subscription was written.
  echo If you expected a full scan, run again and choose 1 (Full scan).
)
pause
