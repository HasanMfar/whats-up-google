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
echo Starting scan... this tests every config one by one, please wait.
echo.
python -m scanner

echo.
echo Done. Import best_subscription.txt into v2rayN - full report is in the reports folder.
pause
