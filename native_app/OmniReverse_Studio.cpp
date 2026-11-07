// OmniReverse Studio v2.1 - Native x64 Windows GUI Application
// Architecture: PerMonitorV2 High-DPI + Common Controls v6 TaskDialogIndirect + Resizable Report Dialog + Hardened PE/Crypto/PID Engine

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

typedef BOOL (WINAPI *PFN_GetOpenFileNameW)(LPOPENFILENAMEW);
typedef BOOL (WINAPI *PFN_SetProcessDpiAwarenessContext)(HANDLE);
typedef UINT (WINAPI *PFN_GetDpiForWindow)(HWND);

static void EnablePerMonitorDpiAwareness() {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) return;
    auto fnSetCtx = (PFN_SetProcessDpiAwarenessContext)GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
    if (fnSetCtx) {
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == ((DPI_AWARENESS_CONTEXT)-4)
        if (fnSetCtx((HANDLE)(LONG_PTR)-4)) return;
        fnSetCtx((HANDLE)(LONG_PTR)-3);
    }
}

static UINT QueryWindowDpi(HWND hwnd) {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32 && hwnd) {
        auto fnGetDpi = (PFN_GetDpiForWindow)GetProcAddress(hUser32, "GetDpiForWindow");
        if (fnGetDpi) {
            UINT dpi = fnGetDpi(hwnd);
            if (dpi >= 96) return dpi;
        }
    }
    return 96;
}

static HANDLE ActivateV6Context(ULONG_PTR* outCookie) {
    *outCookie = 0;
    wchar_t selfPath[2048] = {};
    if (GetModuleFileNameW(NULL, selfPath, 2048) > 0) {
        ACTCTXW selfCtx = { sizeof(selfCtx) };
        selfCtx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
        selfCtx.lpSource = selfPath;
        selfCtx.lpResourceName = MAKEINTRESOURCEW(1);
        HANDLE hSelf = CreateActCtxW(&selfCtx);
        if (hSelf != INVALID_HANDLE_VALUE) {
            if (ActivateActCtx(hSelf, outCookie)) return hSelf;
            ReleaseActCtx(hSelf);
        }
    }

    ACTCTXW actCtx = { sizeof(actCtx) };
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring shellPath = std::wstring(sysDir) + L"\\shell32.dll";
    actCtx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
    actCtx.lpSource = shellPath.c_str();
    actCtx.lpResourceName = MAKEINTRESOURCEW(124);
    HANDLE hCtx = CreateActCtxW(&actCtx);
    if (hCtx != INVALID_HANDLE_VALUE) {
        if (!ActivateActCtx(hCtx, outCookie)) {
            *outCookie = 0;
        }
    }
    return hCtx;
}

static void DeactivateV6Context(HANDLE hCtx, ULONG_PTR cookie) {
    if (cookie) DeactivateActCtx(0, cookie);
    if (hCtx != INVALID_HANDLE_VALUE && hCtx != NULL) ReleaseActCtx(hCtx);
}

typedef HRESULT (WINAPI *PFN_TaskDialogIndirect)(
    const TASKDIALOGCONFIG *pTaskConfig,
    int *pnButton,
    int *pnRadioButton,
    BOOL *pfVerificationFlagChecked
);
typedef BOOL (WINAPI *PFN_InitCommonControlsEx)(const INITCOMMONCONTROLSEX *);

static HMODULE EnsureComCtlV6Loaded() {
    // Must use SxS-aware LoadLibraryW under active v6 Activation Context (never LOAD_LIBRARY_SEARCH_SYSTEM32,
    // which forces System32\comctl32.dll v5.82 and breaks Ordinal 345 / TaskDialogIndirect in SxS-dependent DLLs).
    HMODULE hComCtl = LoadLibraryW(L"comctl32.dll");
    if (hComCtl) {
        auto fnInit = (PFN_InitCommonControlsEx)GetProcAddress(hComCtl, "InitCommonControlsEx");
        if (fnInit) {
            INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES | ICC_LINK_CLASS };
            fnInit(&icc);
        }
    }
    return hComCtl;
}

struct FallbackMenuState {
    const TASKDIALOGCONFIG* ptc;
    int selectedId;
};

static INT_PTR CALLBACK FallbackMenuDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_INITDIALOG) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, lp);
        return TRUE;
    }
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        auto* st = (FallbackMenuState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (id == IDCANCEL) {
            if (st) st->selectedId = IDCANCEL;
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        if (st && st->ptc && st->ptc->pButtons) {
            for (UINT i = 0; i < st->ptc->cButtons; i++) {
                if (st->ptc->pButtons[i].nButtonID == id) {
                    st->selectedId = id;
                    EndDialog(hwnd, id);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static HRESULT ShowFallbackTaskDialog(const TASKDIALOGCONFIG* ptc, int* pBtn) {
    if (!ptc || !pBtn || !ptc->pButtons || ptc->cButtons == 0) return E_FAIL;
    std::vector<BYTE> raw(16384, 0);
    BYTE* p = raw.data();
    auto ww = [&](WORD v) { *(WORD*)p = v; p += 2; };
    auto wd = [&](DWORD v) { *(DWORD*)p = v; p += 4; };
    auto ws = [&](const wchar_t* s) {
        if (!s) { *(WORD*)p = 0; p += 2; return; }
        while (*s) {
            wchar_t ch = *s++;
            if (ch == L'\n') { *(WORD*)p = L' '; p += 2; *(WORD*)p = L'-'; p += 2; *(WORD*)p = L' '; p += 2; }
            else { *(WORD*)p = (WORD)ch; p += 2; }
        }
        *(WORD*)p = 0; p += 2;
    };
    auto al = [&]() { while ((p - raw.data()) % 4) *p++ = 0; };

    WORD dlgH = (WORD)(48 + ptc->cButtons * 24);
    wd(DS_SETFONT | DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU);
    wd(0);
    ww((WORD)(1 + ptc->cButtons));
    ww(0); ww(0); ww(380); ww(dlgH);
    ww(0); ww(0);
    ws(ptc->pszWindowTitle ? ptc->pszWindowTitle : L"OmniReverse Studio v2.1");
    ww(9); ws(L"Segoe UI");

    al();
    wd(WS_CHILD | WS_VISIBLE | SS_LEFT); wd(0);
    ww(10); ww(8); ww(360); ww(22); ww(0xFFFF);
    ww(0xFFFF); ww(0x0082);
    ws(ptc->pszMainInstruction ? ptc->pszMainInstruction : L"Secim yapin:");
    ww(0);

    for (UINT i = 0; i < ptc->cButtons; i++) {
        al();
        DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | ((i == 0) ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON);
        wd(style); wd(0);
        ww(10); ww((WORD)(34 + i * 22)); ww(360); ww(19);
        ww((WORD)ptc->pButtons[i].nButtonID);
        ww(0xFFFF); ww(0x0080);
        ws(ptc->pButtons[i].pszButtonText);
        ww(0);
    }

    FallbackMenuState st = { ptc, IDCANCEL };
    INT_PTR res = DialogBoxIndirectParamW(GetModuleHandleW(NULL), (DLGTEMPLATE*)raw.data(), NULL, FallbackMenuDlgProc, (LPARAM)&st);
    if (res <= 0) return E_FAIL;
    *pBtn = st.selectedId;
    return S_OK;
}

static HRESULT SafeTaskDialogIndirect(const TASKDIALOGCONFIG* ptc, int* pBtn) {
    ULONG_PTR cookie = 0;
    HANDLE hCtx = ActivateV6Context(&cookie);

    HMODULE hComCtl = EnsureComCtlV6Loaded();
    if (hComCtl) {
        // Resolve strictly by exported symbol name (never Ordinal 345) so v5.82 fallback never triggers ordinal fault
        auto fn = (PFN_TaskDialogIndirect)GetProcAddress(hComCtl, "TaskDialogIndirect");
        if (fn) {
            HRESULT hr = fn(ptc, pBtn, NULL, NULL);
            DeactivateV6Context(hCtx, cookie);
            if (SUCCEEDED(hr)) return hr;
            return ShowFallbackTaskDialog(ptc, pBtn);
        }
    }
    DeactivateV6Context(hCtx, cookie);
    return ShowFallbackTaskDialog(ptc, pBtn);
}

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

static std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    if (sz <= 0) return L"";
    std::wstring out(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &out[0], sz);
    return out;
}

static std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    if (sz <= 0) return "";
    std::string out(sz, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &out[0], sz, NULL, NULL);
    return out;
}

static std::wstring GetEnvVarW(const wchar_t* name) {
    wchar_t buf[2048] = {};
    DWORD n = GetEnvironmentVariableW(name, buf, 2048);
    return (n > 0 && n < 2048) ? std::wstring(buf, n) : L"";
}

static std::wstring EnsureTrailingSlash(std::wstring p) {
    if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p += L'\\';
    return p;
}

static std::wstring GetSelfDir() {
    wchar_t buf[2048] = {};
    GetModuleFileNameW(NULL, buf, 2048);
    std::wstring s(buf);
    auto p = s.rfind(L'\\');
    return (p != std::wstring::npos) ? s.substr(0, p + 1) : L".\\";
}

static bool FileExists(const std::wstring& p) {
    DWORD attr = GetFileAttributesW(p.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring ResolveStudioRoot() {
    std::wstring envRoot = GetEnvVarW(L"OMNI_STUDIO_ROOT");
    if (!envRoot.empty()) {
        std::wstring d = EnsureTrailingSlash(envRoot);
        if (FileExists(d + L"omni_cli_runner.py")) return d;
    }
    std::wstring selfDir = GetSelfDir();
    if (FileExists(selfDir + L"omni_cli_runner.py")) return selfDir;

    std::wstring parentDir = selfDir + L"..\\";
    if (FileExists(parentDir + L"omni_cli_runner.py")) return parentDir;

    std::wstring userProfile = GetEnvVarW(L"USERPROFILE");
    if (!userProfile.empty()) {
        std::wstring wsDir = EnsureTrailingSlash(userProfile) + L"Documents\\projelerim\\OmniReverse-Studio\\";
        if (FileExists(wsDir + L"omni_cli_runner.py")) return wsDir;
    }
    return selfDir;
}

static std::wstring LocatePythonExecutable() {
    std::wstring envPy = GetEnvVarW(L"OMNI_PYTHON_EXE");
    if (!envPy.empty() && FileExists(envPy)) return envPy;

    std::wstring studioRoot = ResolveStudioRoot();
    if (FileExists(studioRoot + L".venv\\Scripts\\python.exe")) return studioRoot + L".venv\\Scripts\\python.exe";

    std::wstring localApp = GetEnvVarW(L"LOCALAPPDATA");
    if (!localApp.empty()) {
        std::wstring la = EnsureTrailingSlash(localApp);
        const wchar_t* vers[] = { L"Python312", L"Python313", L"Python311", L"Python310", NULL };
        for (int i = 0; vers[i]; i++) {
            std::wstring cand = la + L"Programs\\Python\\" + vers[i] + L"\\python.exe";
            if (FileExists(cand)) return cand;
        }
    }

    wchar_t found[MAX_PATH] = {};
    if (SearchPathW(NULL, L"python.exe", NULL, MAX_PATH, found, NULL) > 0 && FileExists(found)) {
        return std::wstring(found);
    }
    return L"python.exe";
}

static std::wstring ResolveCompanionDllPath() {
    std::wstring selfDir = GetSelfDir();
    std::wstring studioRoot = ResolveStudioRoot();
    const std::wstring candidates[] = {
        selfDir + L"keyauth_patcher.dll",
        selfDir + L"omni_tracer.dll",
        studioRoot + L"keyauth_patcher.dll",
        studioRoot + L"omni_tracer.dll"
    };
    for (const auto& c : candidates) {
        if (FileExists(c)) return c;
    }
    return selfDir + L"keyauth_patcher.dll";
}

static bool InjectDLL(HANDLE hProc, const std::wstring& dllPath) {
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProc, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), pathBytes, NULL)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLib = hK32 ? GetProcAddress(hK32, "LoadLibraryW") : NULL;
    if (!pLoadLib) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    DWORD waitRes = WaitForSingleObject(hThread, 8000);
    DWORD exitCode = 0;
    if (waitRes == WAIT_OBJECT_0) {
        GetExitCodeThread(hThread, &exitCode);
        // CWE-416 fix: only release remote path buffer once the remote LoadLibraryW thread has exited!
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    }
    CloseHandle(hThread);
    return (waitRes == WAIT_OBJECT_0) && (exitCode != 0);
}

static std::string ReadUtf8FileContent(const std::wstring& path, size_t maxBytes = 8 * 1024 * 1024) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart <= 0) {
        CloseHandle(hFile);
        return "";
    }
    size_t sz = (size_t)fsz.QuadPart;
    if (sz > maxBytes) sz = maxBytes;
    std::string buf(sz, '\0');
    DWORD rd = 0;
    ReadFile(hFile, &buf[0], (DWORD)sz, &rd, NULL);
    buf.resize(rd);
    CloseHandle(hFile);
    return buf;
}

static bool BrowseFile(const wchar_t* title, const wchar_t* filter, std::wstring& out, const std::wstring& initialDir = L"") {
    ULONG_PTR cookie = 0;
    HANDLE hCtx = ActivateV6Context(&cookie);
    EnsureComCtlV6Loaded();
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring comDlgPath = std::wstring(sysDir) + L"\\comdlg32.dll";
    HMODULE hComDlg = LoadLibraryW(comDlgPath.c_str());
    if (!hComDlg) {
        DeactivateV6Context(hCtx, cookie);
        return false;
    }
    auto fnGetOpen = (PFN_GetOpenFileNameW)GetProcAddress(hComDlg, "GetOpenFileNameW");
    if (!fnGetOpen) {
        DeactivateV6Context(hCtx, cookie);
        return false;
    }
    wchar_t buf[2048] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = 2048;
    ofn.lpstrTitle  = title;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!initialDir.empty()) ofn.lpstrInitialDir = initialDir.c_str();
    BOOL ok = fnGetOpen(&ofn);
    DeactivateV6Context(hCtx, cookie);
    if (!ok) return false;
    out = buf;
    return true;
}

static std::string ComputeSHA256(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    uint8_t hash[32] = {};
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
            if (data && len > 0) BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
            BCryptFinishHash(hHash, hash, 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    char hex[65] = {};
    for (int i = 0; i < 32; i++) sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
    return std::string(hex);
}

static double CalcEntropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    size_t counts[256] = {};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)len;
            ent -= p * (log(p) / log(2.0));
        }
    }
    return ent;
}

static wchar_t g_pidBuf[32] = {};
static std::wstring g_reportText;
static std::wstring g_reportFilePath;
static HFONT g_hMonoFont = NULL;

static INT_PTR CALLBACK PidDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM) {
    if (msg == WM_INITDIALOG) {
        SetFocus(GetDlgItem(hwnd, 1001));
        return FALSE;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == IDOK) {
            GetDlgItemTextW(hwnd, 1001, g_pidBuf, 30);
            EndDialog(hwnd, IDOK);
        } else if (LOWORD(wp) == IDCANCEL) {
            EndDialog(hwnd, IDCANCEL);
        }
        return TRUE;
    }
    return FALSE;
}

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
    wd(0); ww(4); ww(0); ww(0); ww(230); ww(84);
    ww(0); ww(0); ws(L"OmniReverse Studio - Canlı Süreç (PID)"); ww(9); ws(L"Segoe UI");

    al();
    wd(WS_CHILD | WS_VISIBLE | SS_LEFT); wd(0);
    ww(7); ww(7); ww(216); ww(12); ww(0xFFFF);
    ww(0xFFFF); ww(0x0082); ws(L"İncelenecek sürecin PID numarasını girin:"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP); wd(0);
    ww(7); ww(22); ww(216); ww(14); ww(1001);
    ww(0xFFFF); ww(0x0081); ws(L""); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP); wd(0);
    ww(7); ww(52); ww(100); ww(16); ww(IDOK);
    ww(0xFFFF); ww(0x0080); ws(L"İncele (Analyze)"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP); wd(0);
    ww(123); ww(52); ww(100); ww(16); ww(IDCANCEL);
    ww(0xFFFF); ww(0x0080); ws(L"İptal"); ww(0);

    g_pidBuf[0] = L'\0';
    INT_PTR r = DialogBoxIndirectParamW(GetModuleHandleW(NULL), (DLGTEMPLATE*)buf, NULL, PidDlgProc, 0);
    if (r != IDOK || g_pidBuf[0] == L'\0') return false;
    wchar_t* endPtr = NULL;
    unsigned long parsed = wcstoul(g_pidBuf, &endPtr, 10);
    if (parsed == 0 || parsed > 0xFFFFFFFCUL) return false;
    outPid = (DWORD)parsed;
    return true;
}

static void CopyToClipboard(HWND hwnd, const std::wstring& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem) {
        void* ptr = GlobalLock(hMem);
        if (ptr) {
            memcpy(ptr, text.c_str(), bytes);
            GlobalUnlock(hMem);
            if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
                GlobalFree(hMem);
            }
        } else {
            GlobalFree(hMem);
        }
    }
    CloseClipboard();
}

static void LayoutReportDialog(HWND hwnd, int clientW, int clientH) {
    UINT dpi = QueryWindowDpi(hwnd);
    int pad = MulDiv(10, (int)dpi, 96);
    int btnH = MulDiv(30, (int)dpi, 96);
    int editH = clientH - (pad * 3) - btnH;
    if (editH < 80) editH = 80;
    int editW = clientW - (pad * 2);
    if (editW < 120) editW = 120;

    HWND hEdit = GetDlgItem(hwnd, 2001);
    HWND hBtnCopy = GetDlgItem(hwnd, 2002);
    HWND hBtnOpen = GetDlgItem(hwnd, 2003);
    HWND hBtnBack = GetDlgItem(hwnd, IDOK);

    if (hEdit) MoveWindow(hEdit, pad, pad, editW, editH, TRUE);
    int btnY = pad * 2 + editH;
    int wCopy = MulDiv(190, (int)dpi, 96);
    int wOpen = MulDiv(220, (int)dpi, 96);
    int wBack = MulDiv(170, (int)dpi, 96);
    if (hBtnCopy) MoveWindow(hBtnCopy, pad, btnY, wCopy, btnH, TRUE);
    if (hBtnOpen) MoveWindow(hBtnOpen, pad * 2 + wCopy, btnY, wOpen, btnH, TRUE);
    int backX = clientW - pad - wBack;
    if (backX < pad * 3 + wCopy + wOpen) backX = pad * 3 + wCopy + wOpen;
    if (hBtnBack) MoveWindow(hBtnBack, backX, btnY, wBack, btnH, TRUE);
}

static void RefreshMonoFontForDpi(HWND hwnd) {
    UINT dpi = QueryWindowDpi(hwnd);
    int fontPx = -MulDiv(10, (int)dpi, 72);
    HFONT hNew = CreateFontW(fontPx, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    if (hNew) {
        HWND hEdit = GetDlgItem(hwnd, 2001);
        if (hEdit) SendMessageW(hEdit, WM_SETFONT, (WPARAM)hNew, TRUE);
        if (g_hMonoFont) DeleteObject(g_hMonoFont);
        g_hMonoFont = hNew;
    }
}

static INT_PTR CALLBACK ReportDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_INITDIALOG) {
        HWND hEdit = GetDlgItem(hwnd, 2001);
        if (hEdit) {
            // Remove 30KB Win32 EDIT control truncation cap (0 == ~2GB limit)
            SendMessageW(hEdit, EM_SETLIMITTEXT, 0, 0);
        }
        RefreshMonoFontForDpi(hwnd);
        if (hEdit) {
            SetDlgItemTextW(hwnd, 2001, g_reportText.c_str());
            SendMessageW(hEdit, EM_SETSEL, 0, 0);
        }
        HWND hBtnOpen = GetDlgItem(hwnd, 2003);
        if (hBtnOpen) EnableWindow(hBtnOpen, (!g_reportFilePath.empty() && FileExists(g_reportFilePath)) ? TRUE : FALSE);
        RECT rc = {};
        GetClientRect(hwnd, &rc);
        LayoutReportDialog(hwnd, rc.right - rc.left, rc.bottom - rc.top);
        return TRUE;
    }
    if (msg == WM_SIZE) {
        LayoutReportDialog(hwnd, LOWORD(lp), HIWORD(lp));
        return TRUE;
    }
    if (msg == WM_DPICHANGED) {
        RECT* prc = (RECT*)lp;
        if (prc) {
            SetWindowPos(hwnd, NULL, prc->left, prc->top, prc->right - prc->left, prc->bottom - prc->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        RefreshMonoFontForDpi(hwnd);
        RECT rc = {};
        GetClientRect(hwnd, &rc);
        LayoutReportDialog(hwnd, rc.right - rc.left, rc.bottom - rc.top);
        return TRUE;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == 2002) {
            CopyToClipboard(hwnd, g_reportText);
            MessageBoxW(hwnd, L"Analiz raporu panoya kopyalandı!", L"OmniReverse Studio", MB_ICONINFORMATION);
        } else if (LOWORD(wp) == 2003 && !g_reportFilePath.empty()) {
            ShellExecuteW(hwnd, L"open", g_reportFilePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
        } else if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
            if (g_hMonoFont) { DeleteObject(g_hMonoFont); g_hMonoFont = NULL; }
            EndDialog(hwnd, LOWORD(wp));
        }
        return TRUE;
    }
    return FALSE;
}

static void ShowReportWindow(const std::string& utf8Report, const std::wstring& savedPath = L"") {
    std::string crlf;
    crlf.reserve(utf8Report.size() + 256);
    for (size_t i = 0; i < utf8Report.size(); i++) {
        if (utf8Report[i] == '\n' && (i == 0 || utf8Report[i - 1] != '\r')) crlf += "\r\n";
        else crlf += utf8Report[i];
    }
    g_reportText = Utf8ToWide(crlf);
    g_reportFilePath = savedPath;

    static DWORD buf[512];
    memset(buf, 0, sizeof(buf));
    BYTE* p = (BYTE*)buf;
    auto ww = [&](WORD  v) { *(WORD*)p  = v; p += 2; };
    auto wd = [&](DWORD v) { *(DWORD*)p = v; p += 4; };
    auto ws = [&](const wchar_t* s) { while (*s) { *(WORD*)p = (WORD)*s++; p += 2; } *(WORD*)p = 0; p += 2; };
    auto al = [&]() { while ((p - (BYTE*)buf) % 4) *p++ = 0; };

    wd(DS_SETFONT | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX);
    wd(0); ww(4); ww(0); ww(0); ww(540); ww(350);
    ww(0); ww(0); ws(L"OmniReverse Studio - Teknik Analiz Raporu"); ww(9); ws(L"Segoe UI");

    al();
    wd(WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | WS_TABSTOP);
    wd(0); ww(7); ww(7); ww(526); ww(312); ww(2001);
    ww(0xFFFF); ww(0x0081); ws(L""); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP); wd(0);
    ww(7); ww(326); ww(135); ww(17); ww(2002);
    ww(0xFFFF); ww(0x0080); ws(L"Panoya Kopyala (Copy)"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP); wd(0);
    ww(150); ww(326); ww(165); ww(17); ww(2003);
    ww(0xFFFF); ww(0x0080); ws(L"Rapor Dosyasını Aç (.md)"); ww(0);

    al();
    wd(WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP); wd(0);
    ww(413); ww(326); ww(120); ww(17); ww(IDOK);
    ww(0xFFFF); ww(0x0080); ws(L"Ana Menüye Dön"); ww(0);

    DialogBoxIndirectParamW(GetModuleHandleW(NULL), (DLGTEMPLATE*)buf, NULL, ReportDlgProc, 0);
}

static std::string SafeCStr(const std::vector<uint8_t>& data, size_t offset, size_t maxLen = 256) {
    if (offset >= data.size()) return "";
    size_t avail = data.size() - offset;
    if (avail > maxLen) avail = maxLen;
    const char* raw = (const char*)(data.data() + offset);
    size_t len = strnlen(raw, avail);
    return std::string(raw, len);
}

static std::string RunNativePEAndCryptoAudit(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "[!] Hata: Dosya acilamadi.";
    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart < 0) {
        CloseHandle(hFile);
        return "[!] Hata: Dosya boyutu okunamadi.";
    }
    if (fsz.QuadPart > (LONGLONG)(256ULL * 1024ULL * 1024ULL)) {
        CloseHandle(hFile);
        return "[!] Guvenlik Siniri: Dosya boyutu 256 MB statik analiz sinirini asiyor.";
    }
    size_t sz = (size_t)fsz.QuadPart;
    std::vector<uint8_t> data(sz);
    DWORD rd = 0;
    if (sz > 0) ReadFile(hFile, data.data(), (DWORD)sz, &rd, NULL);
    data.resize(rd);
    sz = data.size();
    CloseHandle(hFile);

    std::ostringstream out;
    out << "========================================================================\n";
    out << "  OMNIREVERSE STUDIO - NATIVE x64 PE, KRIPTO & LEA/JCC ANALIZ RAPORU\n";
    out << "========================================================================\n";
    out << "[+] Dosya Yolu   : " << WideToUtf8(filePath) << "\n";
    out << "[+] Boyut        : " << sz << " bayt\n";
    out << "[+] SHA-256      : " << ComputeSHA256(data.data(), sz) << "\n";
    out << std::fixed << std::setprecision(3);
    out << "[+] Genel Entropi: " << CalcEntropy(data.data(), sz) << "\n\n";

    if (sz < sizeof(IMAGE_DOS_HEADER) || *(WORD*)data.data() != IMAGE_DOS_SIGNATURE) {
        out << "[*] Not: Hedef standart bir MZ/PE ikili dosyasi degil (Kaynak Kod / ELF / Mach-O / APK / WASM).\n";
        return out.str();
    }

    auto* dos = (const IMAGE_DOS_HEADER*)data.data();
    // CWE-125 fix: reject negative or out-of-range e_lfanew before pointer arithmetic!
    if (dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || (size_t)dos->e_lfanew > sz - sizeof(IMAGE_NT_HEADERS32)) {
        out << "[!] Uyari: Bozuk veya kesilmis PE basligi (gecersiz e_lfanew).\n";
        return out.str();
    }
    size_t ntOff = (size_t)dos->e_lfanew;
    auto* nt32 = (const IMAGE_NT_HEADERS32*)(data.data() + ntOff);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) {
        out << "[!] Uyari: Gecersiz IMAGE_NT_SIGNATURE.\n";
        return out.str();
    }

    WORD optMagic = nt32->OptionalHeader.Magic;
    bool is64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (is64 && ntOff + sizeof(IMAGE_NT_HEADERS64) > sz) {
        out << "[!] Uyari: Kesilmis PE32+ (64-bit) OptionalHeader.\n";
        return out.str();
    }
    auto* nt64 = (const IMAGE_NT_HEADERS64*)(data.data() + ntOff);
    WORD numSecs = nt32->FileHeader.NumberOfSections;
    size_t secTableOff = ntOff + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + nt32->FileHeader.SizeOfOptionalHeader;
    if (numSecs > 128 || secTableOff > sz || (size_t)numSecs * sizeof(IMAGE_SECTION_HEADER) > sz - secTableOff) {
        out << "[!] Uyari: Bozuk PE bolum tablosu (Section Header sinir asimi engellendi).\n";
        return out.str();
    }

    const IMAGE_SECTION_HEADER* firstSec = (const IMAGE_SECTION_HEADER*)(data.data() + secTableOff);
    uint64_t imgBase = is64 ? nt64->OptionalHeader.ImageBase : nt32->OptionalHeader.ImageBase;
    DWORD epRva = is64 ? nt64->OptionalHeader.AddressOfEntryPoint : nt32->OptionalHeader.AddressOfEntryPoint;

    out << "--- [1] PE MIMARI VE BASLIK BILGILERI ---\n";
    out << "  Mimari         : " << (is64 ? "x64 (AMD64)" : "x86 (I386)") << "\n";
    out << "  ImageBase      : 0x" << std::hex << imgBase << "\n";
    out << "  EntryPoint RVA : 0x" << std::hex << epRva << " (VA: 0x" << (imgBase + epRva) << ")\n";
    out << "  Bolum Sayisi   : " << std::dec << numSecs << "\n\n";

    out << "--- [2] PE BOLUMLERI (SECTIONS) & ENTROPI ---\n";
    bool hasVmp = false;
    for (WORD i = 0; i < numSecs; i++) {
        const auto* sec = &firstSec[i];
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        if (_strnicmp(nm, ".vmp", 4) == 0) hasVmp = true;
        size_t rOff = sec->PointerToRawData;
        size_t rSz  = (rOff <= sz && sec->SizeOfRawData <= sz - rOff) ? sec->SizeOfRawData : 0;
        double sEnt = rSz ? CalcEntropy(data.data() + rOff, rSz) : 0.0;
        bool isEx = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isWr = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        out << "  [" << std::setw(8) << std::left << nm << "] RVA: 0x" << std::hex << std::setw(6) << sec->VirtualAddress
            << " | VSize: 0x" << std::setw(6) << sec->Misc.VirtualSize
            << " | RawSz: 0x" << std::setw(6) << sec->SizeOfRawData
            << " | Entropi: " << std::dec << sEnt
            << " | " << (isEx ? "EXEC " : "") << (isWr ? "WRITE " : "") << "\n";
    }
    out << "  [Koruyucu Tespiti] : " << (hasVmp ? "VMProtect (.vmp bolumu tespit edildi -> HWBP DR0/DR1 + VEH onerilir)" : "Standart PE (MinHook / IAT Hook uygun)") << "\n\n";

    out << "--- [3] 4-ASAMALI NATIVE KRIPTO PROLOGLARI (Priority 0/1/2/3 Ed25519 & SigVerify) ---\n";
    static const uint8_t kSodiumProl[] = { 0x40,0x53,0x55,0x56,0x57,0x41,0x56,0x48,0x81,0xEC,0x80,0x02,0x00,0x00 };
    static const uint8_t kWrapHead[]   = { 0x48,0x83,0xEC,0x38,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,0xE8 };
    static const uint8_t kWrapTail[]   = { 0x48,0x83,0xC4,0x38,0xC3 };
    static const uint8_t kSigProl[]    = { 0x40,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x20,0x01,0x00,0x00 };
    static const uint8_t kSigPost[]    = { 0x48,0x33,0xC4,0x48,0x89,0x84,0x24,0x10,0x01,0x00,0x00,0x4D,0x8B,0xF0,0x48,0x8B,0xDA,0x48,0x8B,0xF1 };
    int prolHits = 0;
    for (WORD i = 0; i < numSecs; i++) {
        const auto* sec = &firstSec[i];
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        size_t rOff = sec->PointerToRawData, rSz = sec->SizeOfRawData;
        if (rOff > sz || rSz > sz - rOff) continue;
        const uint8_t* sb = data.data() + rOff;
        for (size_t j = 0; j + sizeof(kSodiumProl) <= rSz; j++) {
            if (memcmp(sb + j, kSodiumProl, sizeof(kSodiumProl)) == 0) {
                DWORD rva = sec->VirtualAddress + (DWORD)j;
                out << "  [+] [Priority 0] libsodium ed25519_verify_detached prologu -> RVA: 0x" << std::hex << rva << " (VA: 0x" << (imgBase + rva) << ")\n";
                prolHits++;
            }
        }
        size_t wTotal = sizeof(kWrapHead) + 4 + sizeof(kWrapTail);
        for (size_t j = 0; j + wTotal <= rSz; j++) {
            if (memcmp(sb + j, kWrapHead, sizeof(kWrapHead)) == 0 &&
                memcmp(sb + j + sizeof(kWrapHead) + 4, kWrapTail, sizeof(kWrapTail)) == 0) {
                int32_t rel = *(const int32_t*)(sb + j + sizeof(kWrapHead));
                DWORD wrapRva = sec->VirtualAddress + (DWORD)j;
                DWORD targetRva = sec->VirtualAddress + (DWORD)(j + sizeof(kWrapHead) + 4) + rel;
                out << "  [+] [Priority 1] libsodium Wrapper (sub rsp,38h; call) -> Wrapper RVA: 0x" << std::hex << wrapRva
                    << " | Hedef RVA: 0x" << targetRva << "\n";
                prolHits++;
            }
        }
        size_t sTotal = sizeof(kSigProl) + 7 + sizeof(kSigPost);
        for (size_t j = 0; j + sTotal <= rSz; j++) {
            if (memcmp(sb + j, kSigProl, sizeof(kSigProl)) == 0 &&
                memcmp(sb + j + sizeof(kSigProl) + 7, kSigPost, sizeof(kSigPost)) == 0) {
                DWORD rva = sec->VirtualAddress + (DWORD)j;
                out << "  [+] [Priority 3] SigVerifyFunc (DR1 HWBP RAX=0xA58F hedefi) -> RVA: 0x" << std::hex << rva << " (VA: 0x" << (imgBase + rva) << ")\n";
                prolHits++;
            }
        }
    }
    if (prolHits == 0) out << "  [-] Statik libsodium/Ed25519 prologu bulunamadi.\n";

    out << "\n--- [4] MULTI-RUNTIME (.NET / GO / RUST / JAVA) & TLS/KRIPTO STACK TESPITI ---\n";
    auto hasBytes = [&](const char* pat, size_t plen = 0) -> bool {
        if (plen == 0) plen = strlen(pat);
        if (sz < plen) return false;
        for (size_t i = 0; i + plen <= sz; i++) {
            if (memcmp(data.data() + i, pat, plen) == 0) return true;
        }
        return false;
    };
    if (hasBytes("mscoree.dll") || hasBytes("coreclr.dll") || hasBytes("System.Net.Security") || hasBytes("SslStream"))
        out << "  [+] Runtime Stack : .NET / C# (CLR / CoreCLR -> SslStream/sspicli + WinHTTP + BCryptDecrypt kancalari aktif)\n";
    if (hasBytes("Go buildinf:") || hasBytes("crypto/tls.(*Conn).Read") || hasBytes("runtime.main"))
        out << "  [+] Runtime Stack : Go (Golang -> crypto/tls + WSARecv + CertVerify kancalari aktif)\n";
    if (hasBytes("rust_panic") || hasBytes("core::panicking") || hasBytes("rustls") || hasBytes("ring::signature"))
        out << "  [+] Runtime Stack : Rust (rustls / ring / native-tls -> SChannel/WinHTTP/BCrypt/WSARecv kancalari aktif)\n";
    if (hasBytes("jvm.dll") || hasBytes("JNI_CreateJavaVM") || hasBytes("sunmscapi"))
        out << "  [+] Runtime Stack : Java / JVM (SunMSCAPI + Socket/TLS kancalari aktif)\n";

    const char* apiMarkers[] = {
        "DecryptMessage", "InitializeSecurityContext", "WinHttpReadData", "WinHttpQueryHeaders",
        "InternetReadFile", "HttpQueryInfo", "SSL_read", "BCryptVerifySignature", "BCryptDecrypt",
        "NCryptVerifySignature", "NCryptDecrypt", "CryptVerifySignature", "CryptDecrypt",
        "CertVerifyCertificateChainPolicy", "WinVerifyTrust", NULL
    };
    out << "  [*] Tespit Edilen TLS & Custom Kripto API'leri:\n";
    int apiHits = 0;
    for (int a = 0; apiMarkers[a]; a++) {
        if (hasBytes(apiMarkers[a])) {
            out << "      -> " << apiMarkers[a] << "\n";
            apiHits++;
        }
    }
    if (apiHits == 0) out << "      -> (Dinamik GetProcAddress veya saf gomulu kripto)\n";

    out << "\n--- [5] RIP-BAGIL LEA XREF & EVRENSEL (KEYAUTH + NON-KEYAUTH) DALLANMA ANALIZI ---\n";
    const char* needles[] = {
        "Signature verification failed", "x-signature-ed25519", "x-signature-timestamp",
        "\"success\":false", "Invalid license", "License expired", "Unauthorized",
        "Invalid key", "Invalid serial", "Activation failed", "HWID mismatch",
        "Trial expired", "Verification failed", "DecryptMessage", "SSL_read", "BCryptVerifySignature", NULL
    };
    int xrefTotal = 0;
    for (int k = 0; needles[k]; k++) {
        size_t nlen = strlen(needles[k]);
        for (WORD i = 0; i < numSecs; i++) {
            const auto* sec = &firstSec[i];
            size_t rOff = sec->PointerToRawData, rSz = sec->SizeOfRawData;
            if (rOff > sz || rSz > sz - rOff || rSz < nlen) continue;
            bool foundNeedleInSec = false;
            for (size_t j = 0; j + nlen <= rSz; j++) {
                if (memcmp(data.data() + rOff + j, needles[k], nlen) == 0) {
                    DWORD strRva = sec->VirtualAddress + (DWORD)j;
                    out << "  [*] String: \"" << needles[k] << "\" @ RVA 0x" << std::hex << strRva << "\n";
                    xrefTotal++;
                    for (WORD ei = 0; ei < numSecs; ei++) {
                        const auto* exSec = &firstSec[ei];
                        if (!(exSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                        size_t eOff = exSec->PointerToRawData, eSz = exSec->SizeOfRawData;
                        if (eOff > sz || eSz > sz - eOff || eSz < 7) continue;
                        const uint8_t* eb = data.data() + eOff;
                        for (size_t m = 0; m + 7 <= eSz; m++) {
                            if (eb[m] == 0x48 && eb[m + 1] == 0x8D && (eb[m + 2] == 0x0D || eb[m + 2] == 0x15)) {
                                int32_t disp = *(const int32_t*)(eb + m + 3);
                                DWORD leaRva = exSec->VirtualAddress + (DWORD)m;
                                if ((int64_t)leaRva + 7 + disp == (int64_t)strRva) {
                                    out << "      -> LEA XRef @ RVA 0x" << std::hex << leaRva << " (VA: 0x" << (imgBase + leaRva) << ")\n";
                                    size_t scanStart = (m > 64) ? (m - 64) : 0;
                                    for (size_t b = scanStart; b + 2 <= m; b++) {
                                        if (b + 4 <= m && eb[b] == 0x85 && eb[b + 1] == 0xC0 && (eb[b + 2] == 0x74 || (eb[b + 2] == 0x0F && eb[b + 3] == 0x84))) {
                                            DWORD jccRva = exSec->VirtualAddress + (DWORD)(b + 2);
                                            out << "         [!] TEST EAX,EAX + JE Dallanmasi (74->EB / 0F84->90E9) @ RVA 0x" << std::hex << jccRva << "\n";
                                        } else if (b + 6 <= m && eb[b] == 0x0F && eb[b + 1] == 0x85) {
                                            int32_t d32 = *(const int32_t*)(eb + b + 2);
                                            if (abs((int)(b + 6 + d32) - (int)m) <= 16) {
                                                out << "         [!] JNE rel32 Dallanmasi (0F85->6xNOP) @ RVA 0x" << std::hex << (exSec->VirtualAddress + (DWORD)b) << "\n";
                                            }
                                        } else if (eb[b] == 0x75) {
                                            int8_t d8 = (int8_t)eb[b + 1];
                                            if (abs((int)(b + 2 + d8) - (int)m) <= 16) {
                                                out << "         [!] JNE rel8 Dallanmasi (75->2xNOP) @ RVA 0x" << std::hex << (exSec->VirtualAddress + (DWORD)b) << "\n";
                                            }
                                        }
                                    }
                                    size_t back512 = (m > 512) ? (m - 512) : 0;
                                    for (size_t p = (m > 7 ? m - 7 : 0); p >= back512 && p < m; p--) {
                                        if (eb[p] == 0xE8 && eb[p + 5] == 0x85 && eb[p + 6] == 0xC0) {
                                            int32_t rel = *(const int32_t*)(eb + p + 1);
                                            DWORD callRva = exSec->VirtualAddress + (DWORD)p;
                                            DWORD fnRva = callRva + 5 + rel;
                                            out << "         [+] [Priority 2] 512B Geriye Dogru CALL+TEST Hedef Fonksiyonu -> RVA: 0x"
                                                << std::hex << fnRva << " (VA: 0x" << (imgBase + fnRva) << ")\n";
                                            break;
                                        }
                                        if (p == back512) break;
                                    }
                                }
                            }
                        }
                    }
                    foundNeedleInSec = true;
                    break;
                }
            }
            (void)foundNeedleInSec;
        }
    }
    if (xrefTotal == 0) out << "  [-] Hedeflenen TLS/Imza string referansi bulunamadi.\n";

    out << "\n--- [6] IAT SLOT ADRESLERI (FirstThunk), SELF-CRC / ANTI-HWBP & TIMEBOMB DENETIMI ---\n";
    auto rvaToFileOff = [&](DWORD rva) -> size_t {
        for (WORD i = 0; i < numSecs; i++) {
            const auto* s = &firstSec[i];
            DWORD vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
            if (rva >= s->VirtualAddress && rva - s->VirtualAddress < vSz) {
                DWORD delta = rva - s->VirtualAddress;
                if (delta >= s->SizeOfRawData) return 0; // Uninitialized BSS
                if (s->PointerToRawData > sz || delta >= sz - s->PointerToRawData) return 0;
                return (size_t)s->PointerToRawData + (size_t)delta;
            }
        }
        return 0;
    };
    DWORD impDirRva = 0;
    if (is64 && nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        impDirRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else if (!is64 && nt32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        impDirRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    int iatPrinted = 0;
    if (impDirRva) {
        size_t impOff = rvaToFileOff(impDirRva);
        if (impOff && impOff <= sz - sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            for (size_t dOff = impOff; dOff <= sz - sizeof(IMAGE_IMPORT_DESCRIPTOR); dOff += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
                const auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)(data.data() + dOff);
                if (!imp->Name) break;
                size_t nameOff = rvaToFileOff(imp->Name);
                if (!nameOff) continue;
                std::string dllName = SafeCStr(data, nameOff, 128);
                if (dllName.empty()) continue;
                DWORD iltRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
                DWORD iatRva = imp->FirstThunk;
                size_t iltOff = rvaToFileOff(iltRva);
                if (!iltOff || !is64) continue;
                for (size_t idx = 0; idx < 4096 && iltOff + (idx + 1) * 8 <= sz; idx++) {
                    uint64_t thunkVal = *(const uint64_t*)(data.data() + iltOff + idx * 8);
                    if (!thunkVal) break;
                    if (thunkVal & IMAGE_ORDINAL_FLAG64) continue;
                    size_t ibnOff = rvaToFileOff((DWORD)(thunkVal & 0x7FFFFFFFULL));
                    if (!ibnOff || ibnOff + 3 >= sz) continue;
                    std::string fnName = SafeCStr(data, ibnOff + 2, 128);
                    if (fnName.empty()) continue;
                    const char* watchFns[] = {
                        "CreateFileW", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
                        "QueryFullProcessImageNameW", "VirtualProtect", "recv", "WSARecv", "connect", "send",
                        "DecryptMessage", "SSL_read", "BCryptVerifySignature", "WinHttpReadData", "InternetReadFile",
                        "exit", "_exit", "abort", "terminate", "MessageBoxA", "MessageBoxW", "CreateThread",
                        "GetProcAddress", "NtGetContextThread", "NtSetContextThread", NULL
                    };
                    for (int w = 0; watchFns[w]; w++) {
                        if (fnName == watchFns[w] && iatPrinted < 25) {
                            DWORD slotRva = iatRva + (DWORD)(idx * 8);
                            out << "  [+] IAT Slot: " << std::setw(14) << std::left << dllName << " ! "
                                << std::setw(26) << fnName << " -> FirstThunk RVA: 0x" << std::hex << slotRva
                                << " (VA: 0x" << (imgBase + slotRva) << ")\n";
                            iatPrinted++;
                            break;
                        }
                    }
                }
            }
        }
    }
    bool hasSelfCrc = hasBytes("CreateFileMappingW") && hasBytes("MapViewOfFile");
    bool hasAntiHwbp = hasBytes("NtGetContextThread") || hasBytes("NtSetContextThread");
    bool hasTimebomb = hasBytes("pool.ntp.org") || hasBytes("time.cloudflare.com") || hasBytes("\xbe\xba\xde\xc0", 4);
    bool hasAdware   = hasBytes("mshta.exe") || hasBytes("vbscript:Execute") || hasBytes("Kariexscontxct");
    out << "  [*] Self-CRC / Disk-Bellek Senkronu (MapViewOfFile) : " << (hasSelfCrc ? "AKTIF (PAGE_WRITECOPY .text senkronu devrede)" : "Yok") << "\n";
    out << "  [*] Anti-HWBP Debug Register Kontrolu (NtGetContext): " << (hasAntiHwbp ? "TESPIT EDILDI (DR0-DR7 sifirlama maskesi aktif)" : "Yok") << "\n";
    out << "  [*] NTP Timebomb (0xC0DEBABE / UDP 123)             : " << (hasTimebomb ? "TESPIT EDILDI (Timebomb imzasi bulundu!)" : "Temiz (Sifir Timebomb)") << "\n";
    out << "  [*] Gizli Reklam / Adware (mshta.exe / Popup)       : " << (hasAdware ? "TESPIT EDILDI (Reklam tetikleyicisi bulundu!)" : "Temiz (Sifir Adware)") << "\n";
    return out.str();
}

static std::string RunLiveProcessInspection(DWORD pid) {
    std::ostringstream out;
    out << "========================================================================\n";
    out << "  OMNIREVERSE STUDIO - CANLI SUREC (PID: " << pid << ") BELLEK & MODUL ANALIZI\n";
    out << "========================================================================\n\n";

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        out << "[!] Hata: Surec modulleri okunamadi (PID: " << pid << ", Hata Kodu: " << GetLastError() << ").\n";
        out << "    Lutfen PID numarasini kontrol edin ve yonetici olarak calistirdiginizdan emin olun.\n";
        return out.str();
    }

    out << "--- [1] YUKLU MODULLER & TLS/KRIPTO KUTUPHANELERI ---\n";
    MODULEENTRY32W me = { sizeof(me) };
    int modCount = 0;
    std::vector<std::string> tlsLibs;
    if (Module32FirstW(hSnap, &me)) {
        do {
            modCount++;
            std::string mName = WideToUtf8(me.szModule);
            if (modCount <= 35) {
                out << "  [0x" << std::hex << std::setw(12) << std::setfill('0') << (uintptr_t)me.modBaseAddr
                    << std::setfill(' ') << std::dec << "] (" << std::setw(7) << (me.modBaseSize / 1024) << " KB) "
                    << mName << "\n";
            }
            const char* watch[] = { "secur32", "sspicli", "bcrypt", "ncrypt", "crypt32", "libssl", "libcrypto", "ws2_32", "winhttp", "wininet", NULL };
            std::string low = mName;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            for (int w = 0; watch[w]; w++) {
                if (low.find(watch[w]) != std::string::npos) {
                    char b[32] = {};
                    sprintf_s(b, "%llx", (unsigned long long)me.modBaseAddr);
                    tlsLibs.push_back(mName + " (@ 0x" + std::string(b) + ")");
                    break;
                }
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    out << "  Toplam Modul Sayisi: " << modCount << "\n\n";

    out << "--- [2] TESPIT EDILEN AG / TLS / KRIPTO MODULLERI ---\n";
    if (tlsLibs.empty()) out << "  [-] Standart TLS/Kripto DLL'i gorulmedi.\n";
    else for (auto& t : tlsLibs) out << "  [+] " << t << "\n";

    out << "\n--- [3] SANAL BELLEK (VIRTUAL MEMORY) & RWX ANOMALI TARAMASI ---\n";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        MEMORY_BASIC_INFORMATION mbi = {};
        uint8_t* addr = nullptr;
        size_t privPages = 0, rwxPages = 0, totalPrivMB = 0;
        while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                if (mbi.Type == MEM_PRIVATE) {
                    privPages++;
                    totalPrivMB += mbi.RegionSize;
                }
                if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    rwxPages++;
                    if (rwxPages <= 15) {
                        out << "  [!] RWX Bellek Bolgesi: Base=0x" << std::hex << (uintptr_t)mbi.BaseAddress
                            << " | Boyut=0x" << mbi.RegionSize << std::dec
                            << " | Tip=" << (mbi.Type == MEM_PRIVATE ? "PRIVATE (Olasi Unpack/JIT/Hook)" : "IMAGE/MAPPED") << "\n";
                    }
                }
            }
            uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
        out << "  Ozel (MEM_PRIVATE) Bolge Sayisi : " << privPages << " (" << (totalPrivMB / (1024 * 1024)) << " MB)\n";
        out << "  RWX (Calistirilabilir+Yazilabilir): " << rwxPages << " bolge\n";

        out << "\n--- [3.5] CANLI MSVC std::string (MsvcString Heap/SSO) & TLS/JSON PAYLOAD TARAMASI ---\n";
        uint8_t* scanAddr = nullptr;
        int msvcHits = 0, jsonHits = 0;
        while (VirtualQueryEx(hProc, scanAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize <= 4 * 1024 * 1024) {
                std::vector<uint8_t> page(mbi.RegionSize);
                SIZE_T rdBytes = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, page.data(), mbi.RegionSize, &rdBytes) && rdBytes >= 64) {
                    for (size_t off = 0; off + 32 <= rdBytes; off += 8) {
                        uint64_t sLen = *(const uint64_t*)(page.data() + off + 16);
                        uint64_t sCap = *(const uint64_t*)(page.data() + off + 24);
                        if (sLen >= 6 && sLen <= 15 && sCap == 15 && page[off + sLen] == 0 && msvcHits < 12) {
                            bool printable = true;
                            for (size_t k = 0; k < sLen; k++) {
                                if (page[off + k] < 32 || page[off + k] > 126) { printable = false; break; }
                            }
                            if (printable) {
                                std::string val((const char*)(page.data() + off), sLen);
                                out << "  [+] MsvcString (SSO cap=15) @ 0x" << std::hex << ((uintptr_t)mbi.BaseAddress + off)
                                    << std::dec << " (len=" << sLen << "): \"" << val << "\"\n";
                                msvcHits++;
                            }
                        }
                    }
                    const char* liveNeedles[] = { "\"success\":", "\"nonce\":", "x-signature-ed25519", "HTTP/1.1 200", "Bearer ", NULL };
                    for (int n = 0; liveNeedles[n] && jsonHits < 10; n++) {
                        size_t nlen = strlen(liveNeedles[n]);
                        for (size_t pos = 0; pos + nlen + 32 <= rdBytes; pos++) {
                            if (memcmp(page.data() + pos, liveNeedles[n], nlen) == 0) {
                                std::string snip((const char*)(page.data() + pos), 60);
                                for (char& c : snip) if ((unsigned char)c < 32 || (unsigned char)c > 126) c = '.';
                                out << "  [!] Canli Heap JSON/TLS Yuku @ 0x" << std::hex << ((uintptr_t)mbi.BaseAddress + pos)
                                    << std::dec << ": [" << snip << "]\n";
                                jsonHits++;
                                break;
                            }
                        }
                    }
                }
            }
            if (msvcHits >= 12 && jsonHits >= 10) break;
            uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
            if (next <= scanAddr) break;
            scanAddr = next;
        }
        CloseHandle(hProc);
    } else {
        out << "  [!] OpenProcess(PROCESS_VM_READ) reddedildi (Kod: " << GetLastError() << ").\n";
    }
    return out.str();
}

static std::string RunPythonBridgeCommand(const std::wstring& cmdLine, DWORD timeoutMs = 45000) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    PROCESS_INFORMATION pi = {};
    std::wstring mutableCmd = cmdLine;

    if (!CreateProcessW(NULL, &mutableCmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "[!] Hata: Python analiz koprusu baslatilamadi.";
    }
    CloseHandle(hWrite);

    std::string output;
    output.reserve(32768);
    const size_t kMaxOutputBytes = 16 * 1024 * 1024;
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    char buf[4096];

    while (true) {
        DWORD avail = 0;
        while (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD toRead = (avail > sizeof(buf)) ? (DWORD)sizeof(buf) : avail;
            DWORD readBytes = 0;
            if (!ReadFile(hRead, buf, toRead, &readBytes, NULL) || readBytes == 0) break;
            if (output.size() < kMaxOutputBytes) {
                size_t room = kMaxOutputBytes - output.size();
                output.append(buf, (readBytes < room) ? readBytes : room);
            }
        }
        DWORD waitState = WaitForSingleObject(pi.hProcess, 40);
        if (waitState == WAIT_OBJECT_0) {
            while (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                DWORD toRead = (avail > sizeof(buf)) ? (DWORD)sizeof(buf) : avail;
                DWORD readBytes = 0;
                if (!ReadFile(hRead, buf, toRead, &readBytes, NULL) || readBytes == 0) break;
                if (output.size() < kMaxOutputBytes) {
                    size_t room = kMaxOutputBytes - output.size();
                    output.append(buf, (readBytes < room) ? readBytes : room);
                }
            }
            break;
        }
        if (GetTickCount64() >= deadline) {
            TerminateProcess(pi.hProcess, 1);
            output += "\n[!] Zaman Asimi: Alt islem 45 saniye sinirini astigi icin guvenli sekilde sonlandirildi.\n";
            break;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return output;
}

static std::wstring SaveReportToFile(const std::wstring& baseTarget, const std::string& content) {
    std::wstring outPath = baseTarget + L"_OmniReverse_Raporu.md";
    HANDLE hFile = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        if (!content.empty()) WriteFile(hFile, content.data(), (DWORD)content.size(), &wr, NULL);
        CloseHandle(hFile);
        return outPath;
    }
    wchar_t tmpDir[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tmpDir) > 0) {
        auto slash = baseTarget.find_last_of(L"\\/");
        std::wstring leaf = (slash != std::wstring::npos) ? baseTarget.substr(slash + 1) : L"OmniReverse";
        std::wstring fallbackPath = std::wstring(tmpDir) + leaf + L"_OmniReverse_Raporu.md";
        HANDLE hTmp = CreateFileW(fallbackPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTmp != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            if (!content.empty()) WriteFile(hTmp, content.data(), (DWORD)content.size(), &wr, NULL);
            CloseHandle(hTmp);
            return fallbackPath;
        }
    }
    return L"";
}

static std::wstring ResolveBestHookLogPath(const std::wstring& dirA, const std::wstring& dirB) {
    const wchar_t* logNames[] = { L"keyauth_patcher_log.txt", L"patcher_debug.txt", L"keyauth_response_dump.txt", NULL };
    const std::wstring dirs[] = { EnsureTrailingSlash(dirA), EnsureTrailingSlash(dirB), ResolveStudioRoot() };
    for (const auto& d : dirs) {
        for (int i = 0; logNames[i]; i++) {
            std::wstring cand = d + logNames[i];
            if (FileExists(cand)) return cand;
        }
    }
    return EnsureTrailingSlash(dirA) + L"keyauth_patcher_log.txt";
}

static void LaunchWebStudioAndOpenBrowser() {
    std::wstring pyExe = LocatePythonExecutable();
    std::wstring studioRoot = ResolveStudioRoot();
    std::wstring webScript = studioRoot + L"omni_web_studio.py";
    if (FileExists(webScript)) {
        std::wstring cmd = L"\"" + pyExe + L"\" \"" + webScript + L"\" --host 127.0.0.1 --port 8765";
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, studioRoot.c_str(), &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Sleep(900);
        }
    }
    ShellExecuteW(NULL, L"open", L"http://127.0.0.1:8765", NULL, NULL, SW_SHOWNORMAL);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    EnablePerMonitorDpiAwareness();

    // Headless CLI verification switch: OmniReverse_Studio.exe --audit <target_file> [output_file]
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc >= 3 && wcscmp(argv[1], L"--audit") == 0) {
        std::wstring targetFile = argv[2];
        std::string report = RunNativePEAndCryptoAudit(targetFile);
        if (argc >= 4) {
            HANDLE hOut = CreateFileW(argv[3], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOut != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hOut, report.data(), (DWORD)report.size(), &wr, NULL);
                CloseHandle(hOut);
            }
        } else {
            HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hStdOut && hStdOut != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hStdOut, report.data(), (DWORD)report.size(), &wr, NULL);
            }
        }
        LocalFree(argv);
        return 0;
    }
    if (argv) LocalFree(argv);

    EnableDebugPrivilege();
    std::wstring selfDir = GetSelfDir();
    std::wstring studioRoot = ResolveStudioRoot();
    std::wstring pyExe = LocatePythonExecutable();
    std::wstring cliRunner = studioRoot + L"omni_cli_runner.py";
    HANDLE hModeMutex = NULL;

    while (true) {
        static const TASKDIALOG_BUTTON kModeButtons[] = {
            { 100, L"Protected\nVMProtect or obfuscated application (HWBP DR0/DR1 + VEH + 5-Stage OmniReverse Pipeline)" },
            { 101, L"Non-Protected\nStandard application (MinHook / IAT Hook + Instant Native C++ PE/TLS/LEA Triage)" },
        };
        TASKDIALOGCONFIG tdc = {};
        tdc.cbSize             = sizeof(tdc);
        tdc.pszWindowTitle     = L"OmniReverse Studio v2.1 (x64 Native + Web Studio + KeyAuth Tracer)";
        tdc.pszMainInstruction = L"Uygulama Koruma Seviyesini Seçin (Select Target Mode)";
        tdc.pszContent         = L"Hedef uygulamanın koruma seviyesini seçin (Named Mutex ile Tracer DLL ve 18 Analiz Motoruna aktarılır):";
        tdc.pButtons           = kModeButtons;
        tdc.cButtons           = 2;
        tdc.dwFlags            = TDF_USE_COMMAND_LINKS;

        int modeResult = 0;
        if (FAILED(SafeTaskDialogIndirect(&tdc, &modeResult)) || modeResult == 0 || modeResult == IDCANCEL)
            break;

        bool isProtected = (modeResult == 100);
        if (hModeMutex) { CloseHandle(hModeMutex); hModeMutex = NULL; }
        hModeMutex = CreateMutexW(NULL, FALSE, isProtected ? L"KeyAuthPatcher_Protected" : L"KeyAuthPatcher_NonProtected");

        static const TASKDIALOG_BUTTON kMethodButtons[] = {
            { 200, L"Running process (PID)\nÇalışan sürece PID ile DLL enjekte et + Canlı Modül / RWX / MsvcString Heap Analizi" },
            { 201, L"Launch application (CREATE_SUSPENDED)\nEXE seç, askıda başlat, Tracer DLL enjekte et ve SChannel/OpenSSL/Ed25519 loglarını yakala" },
            { 202, L"Deep Reverse & Native PE/LEA/Crypto Audit\n5-Aşamalı OmniReverse Pipeline (CAPA, IoC, Deobfuscation) + 4-Aşamalı Verifier & IAT Taraması" },
            { 203, L"Dynamic Memory Unpacker & Unicorn Emulator\nThemida/VMProtect RAM Dökümü, LCG Keystream Çözücü, Bytecode VM & Unicorn CPU Emülatörü" },
            { 204, L"Granular, Mobile, Web & SAST Audit (18 Engines)\nPE/ELF/Mach-O Sembol/Capstone, Go/Rust/Flutter, APK ARSC/XRef, WASM, Sourcemap & AST SQLi" },
            { 205, L"View Live Hook / Tracer Log (keyauth_patcher_log.txt)\nEnjekte edilen DLL'in yakaladığı SChannel/OpenSSL/Winsock/Ed25519/HWBP loglarını görüntüle" },
            { 206, L"Export C++ Tracer SDK & RFC 8032 Ed25519 / Z3 MBA / Frida-ADB Suite\nTemiz C++ Tracer SDK dışa aktarımı, RFC 8032 imzalama testi, Z3 SMT MBA & Cihaz Taraması" },
            { 207, L"Cross-Platform Web Studio UI (Tarayıcı Panosu Başlat)\nDuyarlı (Responsive / Dark-Light / PWA) 38-motor Web arayüzünü başlat (http://127.0.0.1:8765)" },
            { 208, L"v3.0 Elite Reverse Suite (20 Yeni Motor)\n.NET CIL/Costura, Scylla IAT, Direct Syscall, YARA, Flutter/Hermes/IL2CPP/IPA, ASAR/PyInstaller/Bun, CFG & Protobuf" },
        };
        TASKDIALOGCONFIG tdc2 = {};
        tdc2.cbSize             = sizeof(tdc2);
        tdc2.pszWindowTitle     = L"OmniReverse Studio v3.0 (x64 Native + Web Studio + 38 Analiz Motoru)";
        tdc2.pszMainInstruction = L"Analiz veya Enjeksiyon Yöntemini Seçin";
        tdc2.pszContent         = isProtected
            ? L"Aktif Mod: Protected (KeyAuthPatcher_Protected Mutex + HWBP/VEH + Derin Pipeline)"
            : L"Aktif Mod: Non-Protected (KeyAuthPatcher_NonProtected Mutex + MinHook/IAT + Hızlı Triage)";
        tdc2.pButtons           = kMethodButtons;
        tdc2.cButtons           = 9;
        tdc2.dwFlags            = TDF_USE_COMMAND_LINKS;

        int methodResult = 0;
        if (FAILED(SafeTaskDialogIndirect(&tdc2, &methodResult)) || methodResult == 0 || methodResult == IDCANCEL)
            continue;

        if (methodResult == 207) {
            LaunchWebStudioAndOpenBrowser();
            continue;
        }

        std::wstring dllPath = ResolveCompanionDllPath();

        if (methodResult == 200) {
            DWORD pid = 0;
            if (!ShowPidInputDialog(pid)) continue;
            std::string rep = RunLiveProcessInspection(pid);
            rep += "\n--- [4] CANLI DLL ENJEKSIYONU (LoadLibraryW Remote Thread) ---\n";
            rep += "  [*] Kullanilan Tracer DLL : " + WideToUtf8(dllPath) + "\n";

            DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
            HANDLE hProc = OpenProcess(access, FALSE, pid);
            if (!hProc) {
                DWORD err = GetLastError();
                rep += "  [!] OpenProcess basarisiz (PID: " + std::to_string(pid) + ", Hata Kodu: " + std::to_string(err) + ").\n";
            } else {
                if (FileExists(dllPath) && InjectDLL(hProc, dllPath)) {
                    rep += "  [+] DLL ENJEKSIYONU BASARILI! (SChannel/OpenSSL/Winsock/BCrypt/HWBP kancalari aktif)\n";
                } else {
                    rep += "  [-] DLL enjeksiyonu basarisiz oldu (Mimari uyumsuzlugu veya erisim engeli).\n";
                }
                CloseHandle(hProc);
            }
            wchar_t tmpDir[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, tmpDir);
            std::wstring pidPath = std::wstring(tmpDir) + L"PID_" + std::to_wstring(pid);
            std::wstring saved = SaveReportToFile(pidPath, rep);
            ShowReportWindow(rep, saved);
        } else if (methodResult == 201) {
            std::wstring targetPath;
            if (!BrowseFile(L"Enjeksiyon ile başlatılacak hedef uygulamayı (.exe) seçin",
                            L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0",
                            targetPath, selfDir))
                continue;

            std::string rep = RunNativePEAndCryptoAudit(targetPath);
            rep += "\n========================================================================\n";
            rep += "  CREATE_SUSPENDED BASLATMA & CANLI TRACER DLL ENJEKSIYONU\n";
            rep += "========================================================================\n";
            rep += "[*] Hedef EXE : " + WideToUtf8(targetPath) + "\n";
            rep += "[*] Tracer DLL: " + WideToUtf8(dllPath) + "\n";
            rep += "[*] Mod Mutex : " + std::string(isProtected ? "KeyAuthPatcher_Protected" : "KeyAuthPatcher_NonProtected") + "\n";

            STARTUPINFOW si = {}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::wstring cmdLine = L"\"" + targetPath + L"\"";
            auto slashPos = targetPath.rfind(L'\\');
            std::wstring workDir = (slashPos != std::wstring::npos) ? targetPath.substr(0, slashPos + 1) : selfDir;
            auto dllSlash = dllPath.rfind(L'\\');
            std::wstring dllDir = (dllSlash != std::wstring::npos) ? dllPath.substr(0, dllSlash + 1) : selfDir;

            if (!CreateProcessW(targetPath.c_str(), &cmdLine[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, workDir.c_str(), &si, &pi)) {
                rep += "[!] Hata: Uygulama CREATE_SUSPENDED ile baslatilamadi (Kod: " + std::to_string(GetLastError()) + ").\n";
            } else {
                rep += "[+] Surec askida (CREATE_SUSPENDED) baslatildi -> PID: " + std::to_string(pi.dwProcessId) + "\n";
                if (FileExists(dllPath) && InjectDLL(pi.hProcess, dllPath)) {
                    rep += "[+] Tracer DLL basariyla enjekte edildi! (SChannel/OpenSSL/Winsock/BCrypt/HWBP aktif)\n";
                    ResumeThread(pi.hThread);
                    rep += "[+] ResumeThread cagrildi, uygulama calisiyor.\n";
                    WaitForSingleObject(pi.hProcess, 2500);
                    std::wstring logPath = ResolveBestHookLogPath(dllDir, workDir);
                    std::string logText = ReadUtf8FileContent(logPath);
                    if (!logText.empty()) {
                        rep += "\n--- [CANLI HOOK LOGU: " + WideToUtf8(logPath) + "] ---\n" + logText + "\n";
                    }
                } else {
                    rep += "[-] DLL enjeksiyonu basarisiz oldu, surec sonlandiriliyor.\n";
                    TerminateProcess(pi.hProcess, 1);
                }
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            std::wstring saved = SaveReportToFile(targetPath, rep);
            ShowReportWindow(rep, saved);
        } else if (methodResult == 202 || methodResult == 203 || methodResult == 204 || methodResult == 208) {
            std::wstring targetPath;
            if (!BrowseFile(L"OmniReverse ile incelenecek dosyayı seçin",
                            L"Tüm Hedefler (*.exe;*.dll;*.apk;*.ipa;*.asar;*.jsc;*.pyc;*.hbc;*.dat;*.elf;*.so;*.dylib;*.sys;*.wasm;*.js;*.map;*.lua;*.py;*.cpp)\0*.exe;*.dll;*.apk;*.ipa;*.asar;*.jsc;*.pyc;*.hbc;*.dat;*.elf;*.so;*.dylib;*.sys;*.wasm;*.js;*.map;*.lua;*.py;*.cpp\0Executable Files (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0",
                            targetPath, selfDir))
                continue;

            std::wstring cliMode = (methodResult == 203) ? L"unpack" : ((methodResult == 204) ? L"granular" : ((methodResult == 208) ? L"v3_suite" : L"all"));
            std::string fullReport = RunNativePEAndCryptoAudit(targetPath);
            if (FileExists(cliRunner)) {
                std::wstring pyCmd = L"\"" + pyExe + L"\" \"" + cliRunner + L"\" \"" + targetPath + L"\" " + cliMode;
                std::string pyOut = RunPythonBridgeCommand(pyCmd);
                if (!pyOut.empty()) {
                    fullReport += "\n\n" + pyOut;
                }
            }
            std::wstring saved = SaveReportToFile(targetPath, fullReport);
            ShowReportWindow(fullReport, saved);
        } else if (methodResult == 205) {
            std::wstring logPath = ResolveBestHookLogPath(selfDir, studioRoot);
            if (!FileExists(logPath)) {
                BrowseFile(L"keyauth_patcher_log.txt veya log dosyasını seçin",
                           L"Log Files (*.txt;*.log)\0*.txt;*.log\0All Files (*.*)\0*.*\0",
                           logPath, selfDir);
            }
            std::string logContent = ReadUtf8FileContent(logPath);
            if (logContent.empty()) {
                logContent = "[*] Henüz keyauth_patcher_log.txt / patcher_debug.txt kaydı bulunamadı.\n"
                             "    Önce 'Launch application (201)' veya 'Running process (200)' ile bir hedef sürece enjeksiyon yapın.";
            }
            ShowReportWindow(logContent, logPath);
        } else if (methodResult == 206) {
            std::wstring exportTarget = studioRoot + L"omni_export_keyauth_patcher";
            std::wstring pyCmd = L"\"" + pyExe + L"\" \"" + cliRunner + L"\" \"" + exportTarget + L"\" sdk_and_tools";
            std::string pyOut = RunPythonBridgeCommand(pyCmd);
            std::wstring saved = SaveReportToFile(studioRoot + L"OmniReverse_SDK_Suite", pyOut);
            ShowReportWindow(pyOut, saved);
        }
    }
    if (hModeMutex) CloseHandle(hModeMutex);
    return 0;
}
