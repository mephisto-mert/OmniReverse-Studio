@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "STUDIO_ROOT=%%~fI"

if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

set "SDK_ROOT=%SCRIPT_DIR%winsdk\Windows Kits\10"
set "SDK_VER=10.0.26100.0"
if exist "%SDK_ROOT%\Include\%SDK_VER%" (
    set "INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\um;%SDK_ROOT%\Include\%SDK_VER%\shared;%SDK_ROOT%\Include\%SDK_VER%\winrt"
    set "LIB=%LIB%;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"
    set "PATH=%PATH%;%SDK_ROOT%\bin\%SDK_VER%\x64;%SDK_ROOT%\bin\x64"
)

cd /d "%STUDIO_ROOT%\templates\native_tls_hwbp\patcher"
del /Q "%STUDIO_ROOT%\keyauth_patcher.dll" 2>nul
cl.exe /nologo /O2 /EHsc /utf-8 /DUNICODE /D_UNICODE /DNDEBUG /D_USRDLL /I"." dllmain.cpp /LD /Fe:"%STUDIO_ROOT%\keyauth_patcher.dll" /link /SUBSYSTEM:WINDOWS
if exist "%STUDIO_ROOT%\keyauth_patcher.dll" (
    copy /Y "%STUDIO_ROOT%\keyauth_patcher.dll" "%STUDIO_ROOT%\omni_tracer.dll" >nul
    if exist "%USERPROFILE%\Desktop\" (
        copy /Y "%STUDIO_ROOT%\keyauth_patcher.dll" "%USERPROFILE%\Desktop\keyauth_patcher.dll" >nul
        copy /Y "%STUDIO_ROOT%\keyauth_patcher.dll" "%USERPROFILE%\Desktop\omni_tracer.dll" >nul
    )
    echo [+] DLL BUILD SUCCESSFUL!
) else (
    echo [-] DLL BUILD FAILED!
    exit /b 1
)
