// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <string>

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

// comctl32 v6 required for TaskDialogIndirect — embedded manifest, no external .manifest file needed
#pragma comment(linker, \
    "/manifestdependency:\"type='win32' " \
    "name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' " \
    "processorArchitecture='amd64' " \
    "publicKeyToken='6595b64144ccf1df' " \
    "language='*'\"")

static void EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

static std::wstring GetSelfDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring s(buf);
    auto p = s.rfind(L'\\');
    return (p != std::wstring::npos) ? s.substr(0, p + 1) : L".\\";
}

static bool FileExists(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static bool BrowseFile(const wchar_t* title, const wchar_t* filter,
                       std::wstring& out, const std::wstring& initialDir = L"") {
    wchar_t buf[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.lpstrFilter  = filter;
    ofn.lpstrFile    = buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrTitle   = title;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!initialDir.empty()) ofn.lpstrInitialDir = initialDir.c_str();
    if (!GetOpenFileNameW(&ofn)) return false;
    out = buf;
    return true;
}

static bool InjectDLL(HANDLE hProc, const std::wstring& dllPath) {
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProc, NULL, pathBytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), pathBytes, NULL)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    FARPROC pLoadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 8000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    return exitCode != 0;
}

static wchar_t g_pidBuf[16] = {};

static INT_PTR CALLBACK PidDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM) {
    if (msg == WM_INITDIALOG) {
        SetFocus(GetDlgItem(hwnd, 1001));
        return FALSE;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == IDOK) {
            GetDlgItemTextW(hwnd, 1001, g_pidBuf, 15);
            EndDialog(hwnd, IDOK);
        } else if (LOWORD(wp) == IDCANCEL) {
            EndDialog(hwnd, IDCANCEL);
        }
        return TRUE;
    }
    return FALSE;
}

// dynamic DLGTEMPLATE — no .rc file needed
static bool ShowPidInputDialog(DWORD& outPid) {
    static DWORD buf[256];
    memset(buf, 0, sizeof(buf));
    BYTE* p = (BYTE*)buf;

    auto ww = [&](WORD  v) { *(WORD*)p  = v; p += 2; };
    auto wd = [&](DWORD v) { *(DWORD*)p = v; p += 4; };
    auto ws = [&](const wchar_t* s) {
        while (*s) { *(WORD*)p = (WORD)*s++; p += 2; }
        *(WORD*)p = 0; p += 2;
    };
    auto al = [&]() { while ((p - (BYTE*)buf) % 4) *p++ = 0; };

    wd(DS_SETFONT | DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU);
    wd(0); ww(4); ww(0); ww(0); ww(200); ww(78);
    ww(0); ww(0); ws(L"KeyAuth Patcher"); ww(9); ws(L"Segoe UI");

    al();
    wd(WS_CHILD | WS_VISIBLE | SS_LEFT); wd(0);
    ww(7); ww(7); ww(186); ww(12); ww(0xFFFF);
    ww(0xFFFF); ww(0x0082); ws(L"Enter process PID:"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP); wd(0);
    ww(7); ww(22); ww(186); ww(14); ww(1001);
    ww(0xFFFF); ww(0x0081); ws(L""); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP); wd(0);
    ww(7); ww(50); ww(85); ww(14); ww(IDOK);
    ww(0xFFFF); ww(0x0080); ws(L"OK"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP); wd(0);
    ww(108); ww(50); ww(85); ww(14); ww(IDCANCEL);
    ww(0xFFFF); ww(0x0080); ws(L"Cancel"); ww(0);

    g_pidBuf[0] = L'\0';
    INT_PTR r = DialogBoxIndirectParamW(GetModuleHandleW(NULL),
                                        (DLGTEMPLATE*)buf, NULL, PidDlgProc, 0);
    if (r != IDOK || g_pidBuf[0] == L'\0') return false;
    outPid = (DWORD)_wtoi(g_pidBuf);
    return outPid > 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    EnableDebugPrivilege();
    std::wstring selfDir = GetSelfDir();

    std::wstring dllPath = selfDir + L"keyauth_patcher.dll";
    if (!FileExists(dllPath)) {
        MessageBoxW(NULL,
            L"keyauth_patcher.dll not found!\nMust be in the same folder as injector.exe.",
            L"KeyAuth Patcher", MB_ICONERROR);
        return 1;
    }

    static const TASKDIALOG_BUTTON kModeButtons[] = {
        { 100, L"Protected\nVMProtect or obfuscated application" },
        { 101, L"Non-Protected\nStandard application" },
    };
    TASKDIALOGCONFIG tdc = {};
    tdc.cbSize             = sizeof(tdc);
    tdc.pszWindowTitle     = L"KeyAuth Patcher";
    tdc.pszMainInstruction = L"Select application type";
    tdc.pButtons           = kModeButtons;
    tdc.cButtons           = 2;
    tdc.dwFlags            = TDF_USE_COMMAND_LINKS;

    int modeResult = 0;
    if (FAILED(TaskDialogIndirect(&tdc, &modeResult, NULL, NULL)) || modeResult == 0)
        return 0;

    bool isProtected = (modeResult == 100);
    // named mutex is how we pass the mode choice to the DLL without a config file
    if (isProtected)
        CreateMutexW(NULL, FALSE, L"KeyAuthPatcher_Protected");
    else
        CreateMutexW(NULL, FALSE, L"KeyAuthPatcher_NonProtected");

    static const TASKDIALOG_BUTTON kInjectButtons[] = {
        { 200, L"Running process\nInject into a running process by PID" },
        { 201, L"Launch application\nSelect an EXE and launch it with injection" },
    };
    TASKDIALOGCONFIG tdc2 = {};
    tdc2.cbSize             = sizeof(tdc2);
    tdc2.pszWindowTitle     = L"KeyAuth Patcher";
    tdc2.pszMainInstruction = L"Select injection method";
    tdc2.pButtons           = kInjectButtons;
    tdc2.cButtons           = 2;
    tdc2.dwFlags            = TDF_USE_COMMAND_LINKS;

    int injectResult = 0;
    if (FAILED(TaskDialogIndirect(&tdc2, &injectResult, NULL, NULL)) || injectResult == 0)
        return 0;

    if (injectResult == 200) {
        DWORD pid = 0;
        if (!ShowPidInputDialog(pid)) return 0;

        DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
        HANDLE hProc = OpenProcess(access, FALSE, pid);
        if (!hProc) {
            DWORD err = GetLastError();
            wchar_t msg[256];
            _snwprintf_s(msg, 256, _TRUNCATE,
                L"Failed to open process (PID %u).\nError code: %u\n"
                L"Make sure the PID is correct and you are running as administrator.",
                pid, err);
            MessageBoxW(NULL, msg, L"KeyAuth Patcher", MB_ICONERROR);
            return 1;
        }

        if (!InjectDLL(hProc, dllPath)) {
            MessageBoxW(NULL, L"DLL injection failed.", L"KeyAuth Patcher", MB_ICONERROR);
            CloseHandle(hProc);
            return 1;
        }

        CloseHandle(hProc);
        return 0;
    }

    std::wstring targetPath;
    if (!BrowseFile(L"Select target application",
                    L"Executable Files\0*.exe\0All Files\0*.*\0",
                    targetPath, selfDir))
        return 0;

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::wstring cmdLine = L"\"" + targetPath + L"\"";

    if (!CreateProcessW(targetPath.c_str(), &cmdLine[0],
                        NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        MessageBoxW(NULL, L"Failed to launch application.", L"KeyAuth Patcher", MB_ICONERROR);
        return 1;
    }

    if (!InjectDLL(pi.hProcess, dllPath)) {
        MessageBoxW(NULL, L"DLL injection failed.", L"KeyAuth Patcher", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 1;
    }

    // resume only after DLL is loaded so hooks are active before any app code runs
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com
