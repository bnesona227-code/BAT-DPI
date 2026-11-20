@echo off
cd /d "%~dp0"
echo [*] Building BAT-DPI-ENGINE v2.0 (Mid-SNI WinDivert Core)...

where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] GCC (MinGW-w64) not found in PATH.
    pause
    exit /b 1
)

if not exist "..\src\windows\WinDivert.dll" (
    echo [ERROR] WinDivert binaries not found in src\windows\
    echo Place windivert.h, WinDivert.dll, WinDivert.lib, WinDivert64.sys into src\windows\
    pause
    exit /b 1
)

gcc ..\src\windows\dpi_engine.c -o ..\src\windows\bat_dpi_engine.exe -O2 -I..\src\windows -L..\src\windows -lWinDivert -lws2_32
if %errorlevel% equ 0 (
    echo [OK] Build complete: src\windows\bat_dpi_engine.exe
) else (
    echo [ERROR] Build failed.
)
pause
