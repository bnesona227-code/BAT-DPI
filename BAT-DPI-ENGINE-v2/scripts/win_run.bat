@echo off
cd /d "%~dp0..\src\windows"
if not exist "bat_dpi_engine.exe" (
    echo [ERROR] bat_dpi_engine.exe not found. Run win_build.bat first!
    pause
    exit /b 1
)
echo [*] Starting BAT-DPI-ENGINE v2.0 (Administrator privileges required)...
bat_dpi_engine.exe
pause
