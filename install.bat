@echo off
REM PC Guard Pro Advanced - Windows Installation Script

echo ==================================================
echo   PC Guard Pro Advanced v2.0 - Installation
echo ==================================================
echo.

REM Check if Python is installed
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation!
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Python %PYTHON_VERSION% found
echo.

REM Check if pip is available
echo Checking pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not available!
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo [OK] pip is available
echo.

REM Create directory structure
echo Creating directory structure...
if not exist "%USERPROFILE%\.pcguard" mkdir "%USERPROFILE%\.pcguard"
if not exist "%USERPROFILE%\.pcguard\yara_rules" mkdir "%USERPROFILE%\.pcguard\yara_rules"
if not exist "%USERPROFILE%\.pcguard\quarantine" mkdir "%USERPROFILE%\.pcguard\quarantine"
if not exist "%USERPROFILE%\.pcguard\logs" mkdir "%USERPROFILE%\.pcguard\logs"

echo [OK] Directories created
echo.

REM Install Python dependencies
echo Installing Python dependencies...
echo This may take a few minutes...
echo.

set FAILED_PACKAGES=

REM Install psutil
echo Installing psutil (Process monitoring)...
python -m pip install psutil --user >nul 2>&1
if errorlevel 1 (
    echo [WARNING] psutil installation failed
    set FAILED_PACKAGES=%FAILED_PACKAGES% psutil
) else (
    echo [OK] psutil installed successfully
)
echo.

REM Install yara-python
echo Installing yara-python (YARA rule engine)...
python -m pip install yara-python --user >nul 2>&1
if errorlevel 1 (
    echo [WARNING] yara-python installation failed
    echo Note: YARA may require Visual C++ Build Tools
    echo Download from: https://visualstudio.microsoft.com/downloads/
    set FAILED_PACKAGES=%FAILED_PACKAGES% yara-python
) else (
    echo [OK] yara-python installed successfully
)
echo.

REM Install requests
echo Installing requests (VirusTotal integration)...
python -m pip install requests --user >nul 2>&1
if errorlevel 1 (
    echo [WARNING] requests installation failed
    set FAILED_PACKAGES=%FAILED_PACKAGES% requests
) else (
    echo [OK] requests installed successfully
)
echo.

REM Copy YARA rules if available
if exist "advanced_malware_rules.yar" (
    echo Installing YARA detection rules...
    copy /Y "advanced_malware_rules.yar" "%USERPROFILE%\.pcguard\yara_rules\" >nul
    echo [OK] YARA rules installed
    echo.
)

REM Summary
echo ==================================================
echo   Installation Summary
echo ==================================================
echo.

if "%FAILED_PACKAGES%"=="" (
    echo [OK] All dependencies installed successfully!
) else (
    echo [WARNING] Some optional dependencies failed to install:
    echo %FAILED_PACKAGES%
    echo.
    echo The application will run with limited functionality.
    echo.
    echo To install missing packages manually:
    echo   python -m pip install%FAILED_PACKAGES%
    echo.
    echo For yara-python, you may need:
    echo   - Visual C++ Build Tools
    echo   - Or download pre-built wheels from:
    echo     https://github.com/VirusTotal/yara-python/releases
)

echo.
echo Installation complete!
echo.
echo Directory structure:
echo   %USERPROFILE%\.pcguard\yara_rules\    - YARA detection rules
echo   %USERPROFILE%\.pcguard\quarantine\    - Quarantined threats
echo   %USERPROFILE%\.pcguard\threats.db     - Threat database
echo.
echo To run PC Guard Pro:
echo   python pc_guard_pro_advanced.py
echo.
echo For best results:
echo   - Right-click and "Run as Administrator"
echo.
echo Next steps:
echo   1. Get a free VirusTotal API key from:
echo      https://www.virustotal.com/gui/join-us
echo   2. Configure the API key in Settings tab
echo   3. Run a Quick Scan to test
echo.
echo ==================================================
echo   Ready to protect your system!
echo ==================================================
echo.

pause
