@echo off
setlocal
chcp 65001 >nul
title OmniReverse Studio - Native TLS, HWBP & PE LEA Auditor
set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY_EXE%" set "PY_EXE=python"

if "%~1"=="" (
    "%PY_EXE%" "%~dp0native_tls_hwbp_engine.py" "%~dp0templates\native_tls_hwbp"
) else (
    "%PY_EXE%" "%~dp0native_tls_hwbp_engine.py" "%~1"
)
echo.
pause
