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

set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY_EXE%" set "PY_EXE=python"

cd /d "%SCRIPT_DIR%"
taskkill /F /IM OmniReverse_Studio.exe >nul 2>&1
del /F /Q "%STUDIO_ROOT%\OmniReverse_Studio.exe" 2>nul
cl.exe /nologo /O2 /EHsc /utf-8 /W3 /DUNICODE /D_UNICODE /DNDEBUG OmniReverse_Studio.cpp /Fe:"%STUDIO_ROOT%\OmniReverse_Studio.exe" /link /SUBSYSTEM:WINDOWS /MANIFEST:NO
if exist "%STUDIO_ROOT%\OmniReverse_Studio.exe" (
    "%PY_EXE%" "%SCRIPT_DIR%embed_manifest.py" "%STUDIO_ROOT%\OmniReverse_Studio.exe"
    if errorlevel 1 (
        echo [-] MANIFEST EMBEDDING / SxS VERIFICATION FAILED!
        exit /b 1
    )
    if exist "%USERPROFILE%\Desktop\" (
        del /F /Q "%USERPROFILE%\Desktop\OmniReverse_Studio.exe" 2>nul
        copy /Y "%STUDIO_ROOT%\OmniReverse_Studio.exe" "%USERPROFILE%\Desktop\OmniReverse_Studio.exe" >nul
        if exist "%STUDIO_ROOT%\keyauth_patcher.dll" copy /Y "%STUDIO_ROOT%\keyauth_patcher.dll" "%USERPROFILE%\Desktop\keyauth_patcher.dll" >nul
        if exist "%STUDIO_ROOT%\omni_tracer.dll" copy /Y "%STUDIO_ROOT%\omni_tracer.dll" "%USERPROFILE%\Desktop\omni_tracer.dll" >nul
    )
    echo [+] CLEAN NATIVE BUILD SUCCESSFUL!
) else (
    echo [-] BUILD FAILED!
    exit /b 1
)
