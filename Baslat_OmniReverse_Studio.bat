@echo off
setlocal
chcp 65001 >nul
title OmniReverse Studio v2.1 - Baslatici
cd /d "%~dp0"
echo ========================================================================
echo   OMNIREVERSE STUDIO v2.1 (x64 Native + KeyAuth Tracer DLL + 18 Motor)
echo ========================================================================
echo [*] Arayuz penceresi aciliyor, lutfen acilan diyalogdan secim yapin...
"%~dp0OmniReverse_Studio.exe"
if %errorlevel% neq 0 (
    echo [!] Uygulama hata kodu ile kapandi: %errorlevel%
    pause
)
