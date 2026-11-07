// ============================================================================
// OmniReverse Studio - Universal Multi-Stack TLS, Crypto & Runtime Interceptor
// Supports:
//   1. Windows Native SChannel (secur32.dll / sspicli.dll) + WinHTTP + WinINet
//   2. Multi-Language Runtimes: .NET/C# (CLR/CoreCLR), Go (crypto/tls), Rust (rustls/ring), Java (JVM/SunMSCAPI)
//   3. Custom Crypto APIs: BCrypt (BCryptDecrypt/BCryptVerifySignature), NCrypt, CryptoAPI, WinTrust, Crypt32
//   4. Universal Non-KeyAuth Applications (Generic REST/JSON/HTTP License & Auth Spoofer + Universal LEA Branch Patcher)
// ============================================================================

#pragma once
#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>

// Forward declarations from dllmain.cpp
static void Log(const std::string& msg);
static const char* memmem_lite(const char* hay, size_t haylen, const char* needle, size_t needlelen);

// ============================================================================
// 1. UNIVERSAL IN-PLACE JSON / HTTP / REST AUTH PAYLOAD SPOOFER
//    Works on ANY application (KeyAuth or Non-KeyAuth, C++, .NET, Go, Rust, Java)
//    Preserves exact byte length so Content-Length, TLS frames & JSON parsers never break.
// ============================================================================
static int UniversalSpoofPayload(char* buf, size_t len, const char* sourceTag) {
    if (!buf || len < 8) return 0;
    int changes = 0;

    // A. Rewrite HTTP 401/403/402/404 status lines to "HTTP/1.1 200 OK" in-place
    const char* httpPrefixes[] = { "HTTP/1.1 401", "HTTP/1.1 403", "HTTP/1.1 402", "HTTP/2 401", "HTTP/2 403" };
    for (const char* hp : httpPrefixes) {
        size_t hlen = strlen(hp);
        if (len >= hlen && memcmp(buf, hp, hlen) == 0) {
            // Find end of status line (\r\n)
            size_t lineEnd = 0;
            while (lineEnd + 1 < len && !(buf[lineEnd] == '\r' && buf[lineEnd + 1] == '\n')) lineEnd++;
            const char* okLine = "HTTP/1.1 200 OK";
            size_t okLen = strlen(okLine);
            if (lineEnd >= okLen) {
                memcpy(buf, okLine, okLen);
                if (lineEnd > okLen) memset(buf + okLen, ' ', lineEnd - okLen);
                changes++;
            }
        }
    }

    // B. Exact-length RFC 8259 JSON boolean & status replacements (5-byte "false" -> "true ")
    struct ExactRule {
        const char* pattern;
        const char* replacement;
        size_t len;
    };
    static const ExactRule kRules[] = {
        { "\"success\":false",         "\"success\":true ",         15 },
        { "\"success\": false",        "\"success\": true ",        16 },
        { "\"valid\":false",           "\"valid\":true ",           13 },
        { "\"valid\": false",          "\"valid\": true ",          14 },
        { "\"is_valid\":false",        "\"is_valid\":true ",        16 },
        { "\"is_valid\": false",       "\"is_valid\": true ",       17 },
        { "\"isValid\":false",         "\"isValid\":true ",         15 },
        { "\"isValid\": false",        "\"isValid\": true ",        16 },
        { "\"authenticated\":false",   "\"authenticated\":true ",   21 },
        { "\"authenticated\": false",  "\"authenticated\": true ",  22 },
        { "\"authorized\":false",      "\"authorized\":true ",      18 },
        { "\"authorized\": false",     "\"authorized\": true ",     19 },
        { "\"licensed\":false",        "\"licensed\":true ",        16 },
        { "\"licensed\": false",       "\"licensed\": true ",       17 },
        { "\"isLicensed\":false",      "\"isLicensed\":true ",      18 },
        { "\"isLicensed\": false",     "\"isLicensed\": true ",     19 },
        { "\"active\":false",          "\"active\":true ",          14 },
        { "\"active\": false",         "\"active\": true ",         15 },
        { "\"is_active\":false",       "\"is_active\":true ",       17 },
        { "\"is_active\": false",      "\"is_active\": true ",      18 },
        { "\"premium\":false",         "\"premium\":true ",         15 },
        { "\"premium\": false",        "\"premium\": true ",        16 },
        { "\"verified\":false",        "\"verified\":true ",        16 },
        { "\"verified\": false",       "\"verified\": true ",       17 },
        { "\"expired\": true",         "\"expired\":false",         15 },
        { "\"banned\": true",          "\"banned\":false",          14 },
        { "\"status\":\"error\"",      "\"status\":\"ok\"   ",      16 },
        { "\"status\": \"error\"",     "\"status\": \"ok\"   ",     17 },
        { "\"status\":\"invalid\"",    "\"status\":\"valid\"  ",    18 },
        { "\"status\": \"invalid\"",   "\"status\": \"valid\"  ",   19 },
        { "\"status\":\"expired\"",    "\"status\":\"active\" ",    18 },
        { "\"status\": \"expired\"",   "\"status\": \"active\" ",   19 },
        { "\"status\":\"failed\"",     "\"status\":\"ok\"    ",     17 },
        { "\"status\": \"failed\"",    "\"status\": \"ok\"    ",    18 },
        { "\"status\":\"unauthorized\"","\"status\":\"authorized\"  ",23 },
    };

    for (const auto& r : kRules) {
        char* cur = buf;
        size_t rem = len;
        while (rem >= r.len) {
            const char* hit = memmem_lite(cur, rem, r.pattern, r.len);
            if (!hit) break;
            char* writable = const_cast<char*>(hit);
            memcpy(writable, r.replacement, r.len);
            changes++;
            size_t adv = (size_t)(writable - cur) + r.len;
            cur += adv;
            rem -= adv;
        }
    }

    if (changes > 0) {
        Log(std::string("[UniversalSpoof:") + sourceTag + "] Patched " + std::to_string(changes) + " auth/license field(s) in-place!");
    }
    return changes;
}

// ============================================================================
// 2. WINHTTP & WININET HOOKS (Windows Native HTTP/TLS Stacks for C++, .NET, Rust)
// ============================================================================
typedef BOOL (WINAPI* WinHttpReadData_t)(LPVOID hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* WinHttpQueryHeaders_t)(LPVOID hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
typedef BOOL (WINAPI* InternetReadFile_t)(LPVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* HttpQueryInfoW_t)(LPVOID hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
typedef BOOL (WINAPI* HttpQueryInfoA_t)(LPVOID hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

static WinHttpReadData_t     orig_WinHttpReadData = nullptr;
static WinHttpQueryHeaders_t orig_WinHttpQueryHeaders = nullptr;
static InternetReadFile_t    orig_InternetReadFile = nullptr;
static HttpQueryInfoW_t      orig_HttpQueryInfoW = nullptr;
static HttpQueryInfoA_t      orig_HttpQueryInfoA = nullptr;

static BOOL WINAPI Hk_WinHttpReadData(LPVOID hRequest, LPVOID lpBuffer, DWORD dwToRead, LPDWORD lpdwRead) {
    BOOL ok = orig_WinHttpReadData ? orig_WinHttpReadData(hRequest, lpBuffer, dwToRead, lpdwRead) : FALSE;
    if (ok && lpBuffer && lpdwRead && *lpdwRead > 0) {
        UniversalSpoofPayload((char*)lpBuffer, *lpdwRead, "WinHttpReadData");
    }
    return ok;
}

// WINHTTP_QUERY_STATUS_CODE = 19, WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
static BOOL WINAPI Hk_WinHttpQueryHeaders(LPVOID hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwLen, LPDWORD lpdwIdx) {
    BOOL ok = orig_WinHttpQueryHeaders ? orig_WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwLen, lpdwIdx) : FALSE;
    if (ok && lpBuffer && lpdwLen && (dwInfoLevel & 0xFFFF) == 19) {
        if (dwInfoLevel & 0x20000000) {
            DWORD code = *(DWORD*)lpBuffer;
            if (code == 401 || code == 403 || code == 402 || code == 404) {
                *(DWORD*)lpBuffer = 200;
                Log("[WinHttpQueryHeaders] Spoofed numeric HTTP status " + std::to_string(code) + " -> 200");
            }
        } else if (*lpdwLen >= 6) {
            wchar_t* ws = (wchar_t*)lpBuffer;
            if (wcsncmp(ws, L"401", 3) == 0 || wcsncmp(ws, L"403", 3) == 0 || wcsncmp(ws, L"402", 3) == 0) {
                wcsncpy_s(ws, (*lpdwLen) / sizeof(wchar_t), L"200", 3);
                Log("[WinHttpQueryHeaders] Spoofed wide HTTP status -> 200");
            }
        }
    }
    return ok;
}

static BOOL WINAPI Hk_InternetReadFile(LPVOID hFile, LPVOID lpBuffer, DWORD dwToRead, LPDWORD lpdwRead) {
    BOOL ok = orig_InternetReadFile ? orig_InternetReadFile(hFile, lpBuffer, dwToRead, lpdwRead) : FALSE;
    if (ok && lpBuffer && lpdwRead && *lpdwRead > 0) {
        UniversalSpoofPayload((char*)lpBuffer, *lpdwRead, "InternetReadFile");
    }
    return ok;
}

static BOOL WINAPI Hk_HttpQueryInfoW(LPVOID hReq, DWORD dwInfo, LPVOID lpBuf, LPDWORD lpdwLen, LPDWORD lpdwIdx) {
    BOOL ok = orig_HttpQueryInfoW ? orig_HttpQueryInfoW(hReq, dwInfo, lpBuf, lpdwLen, lpdwIdx) : FALSE;
    if (ok && lpBuf && lpdwLen && (dwInfo & 0xFFFF) == 19) {
        if (dwInfo & 0x20000000) {
            DWORD c = *(DWORD*)lpBuf;
            if (c == 401 || c == 403 || c == 402) { *(DWORD*)lpBuf = 200; Log("[HttpQueryInfoW] Spoofed status -> 200"); }
        } else if (*lpdwLen >= 6) {
            wchar_t* ws = (wchar_t*)lpBuf;
            if (wcsncmp(ws, L"401", 3) == 0 || wcsncmp(ws, L"403", 3) == 0) { wcsncpy_s(ws, (*lpdwLen)/2, L"200", 3); }
        }
    }
    return ok;
}

static BOOL WINAPI Hk_HttpQueryInfoA(LPVOID hReq, DWORD dwInfo, LPVOID lpBuf, LPDWORD lpdwLen, LPDWORD lpdwIdx) {
    BOOL ok = orig_HttpQueryInfoA ? orig_HttpQueryInfoA(hReq, dwInfo, lpBuf, lpdwLen, lpdwIdx) : FALSE;
    if (ok && lpBuf && lpdwLen && (dwInfo & 0xFFFF) == 19) {
        if (dwInfo & 0x20000000) {
            DWORD c = *(DWORD*)lpBuf;
            if (c == 401 || c == 403 || c == 402) { *(DWORD*)lpBuf = 200; Log("[HttpQueryInfoA] Spoofed status -> 200"); }
        } else if (*lpdwLen >= 3) {
            char* s = (char*)lpBuf;
            if (strncmp(s, "401", 3) == 0 || strncmp(s, "403", 3) == 0) { memcpy(s, "200", 3); }
        }
    }
    return ok;
}

// ============================================================================
// 3. BCRYPT / NCRYPT / CRYPTOAPI / CRYPT32 / WINTRUST CUSTOM CRYPTO HOOKS
//    Covers custom AES/RSA/ECDSA/Ed25519 signature verification & decryption
// ============================================================================
typedef NTSTATUS (WINAPI* BCryptDecrypt_t)(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
typedef NTSTATUS (WINAPI* NCryptVerifySignature_t)(ULONG_PTR hKey, VOID* pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);
typedef NTSTATUS (WINAPI* NCryptDecrypt_t)(ULONG_PTR hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
typedef BOOL     (WINAPI* CryptVerifySignatureW_t)(ULONG_PTR hHash, const BYTE* pbSig, DWORD dwSigLen, ULONG_PTR hPubKey, LPCWSTR sDesc, DWORD dwFlags);
typedef BOOL     (WINAPI* CryptVerifySignatureA_t)(ULONG_PTR hHash, const BYTE* pbSig, DWORD dwSigLen, ULONG_PTR hPubKey, LPCSTR sDesc, DWORD dwFlags);
typedef BOOL     (WINAPI* CryptDecrypt_t)(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
typedef BOOL     (WINAPI* CertVerifyCertificateChainPolicy_t)(LPCSTR pszPolicyOID, LPVOID pChainContext, LPVOID pPolicyPara, LPVOID pPolicyStatus);
typedef LONG     (WINAPI* WinVerifyTrust_t)(HWND hwnd, GUID* pgActionID, LPVOID pWVTData);

static BCryptDecrypt_t                    orig_BCryptDecrypt = nullptr;
static NCryptVerifySignature_t            orig_NCryptVerifySignature = nullptr;
static NCryptDecrypt_t                    orig_NCryptDecrypt = nullptr;
static CryptVerifySignatureW_t            orig_CryptVerifySignatureW = nullptr;
static CryptVerifySignatureA_t            orig_CryptVerifySignatureA = nullptr;
static CryptDecrypt_t                     orig_CryptDecrypt = nullptr;
static CertVerifyCertificateChainPolicy_t orig_CertVerifyCertificateChainPolicy = nullptr;
static WinVerifyTrust_t                   orig_WinVerifyTrust = nullptr;

static NTSTATUS WINAPI Hk_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPadding, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    NTSTATUS st = orig_BCryptDecrypt ? orig_BCryptDecrypt(hKey, pbInput, cbInput, pPadding, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags) : 0;
    if (st == 0 && pbOutput && pcbResult && *pcbResult >= 8) {
        UniversalSpoofPayload((char*)pbOutput, *pcbResult, "BCryptDecrypt");
    }
    return st;
}

static NTSTATUS WINAPI Hk_NCryptVerifySignature(ULONG_PTR, VOID*, PBYTE, DWORD cbHash, PBYTE, DWORD cbSig, DWORD) {
    Log("[NCryptVerifySignature] hashLen=" + std::to_string(cbHash) + " sigLen=" + std::to_string(cbSig) + " -> FORCED STATUS_SUCCESS (0)");
    return 0;
}

static NTSTATUS WINAPI Hk_NCryptDecrypt(ULONG_PTR hKey, PBYTE pbIn, DWORD cbIn, VOID* pPad, PBYTE pbOut, DWORD cbOut, DWORD* pcbRes, DWORD dwFlags) {
    NTSTATUS st = orig_NCryptDecrypt ? orig_NCryptDecrypt(hKey, pbIn, cbIn, pPad, pbOut, cbOut, pcbRes, dwFlags) : 0;
    if (st == 0 && pbOut && pcbRes && *pcbRes >= 8) {
        UniversalSpoofPayload((char*)pbOut, *pcbRes, "NCryptDecrypt");
    }
    return st;
}

static BOOL WINAPI Hk_CryptVerifySignatureW(ULONG_PTR, const BYTE*, DWORD dwSigLen, ULONG_PTR, LPCWSTR, DWORD) {
    Log("[CryptVerifySignatureW] sigLen=" + std::to_string(dwSigLen) + " -> FORCED TRUE");
    return TRUE;
}

static BOOL WINAPI Hk_CryptVerifySignatureA(ULONG_PTR, const BYTE*, DWORD dwSigLen, ULONG_PTR, LPCSTR, DWORD) {
    Log("[CryptVerifySignatureA] sigLen=" + std::to_string(dwSigLen) + " -> FORCED TRUE");
    return TRUE;
}

static BOOL WINAPI Hk_CryptDecrypt(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    BOOL ok = orig_CryptDecrypt ? orig_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen) : FALSE;
    if (ok && pbData && pdwDataLen && *pdwDataLen >= 8) {
        UniversalSpoofPayload((char*)pbData, *pdwDataLen, "CryptDecrypt");
    }
    return ok;
}

struct MiniCertChainPolicyStatus {
    DWORD cbSize;
    DWORD dwError;
    LONG  lChainIndex;
    LONG  lElementIndex;
    PVOID pvExtraPolicyStatus;
};

static BOOL WINAPI Hk_CertVerifyCertificateChainPolicy(LPCSTR pszPolicyOID, LPVOID pChainCtx, LPVOID pPolicyPara, LPVOID pPolicyStatus) {
    BOOL ok = orig_CertVerifyCertificateChainPolicy ? orig_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainCtx, pPolicyPara, pPolicyStatus) : TRUE;
    if (pPolicyStatus) {
        auto* st = (MiniCertChainPolicyStatus*)pPolicyStatus;
        if (st->dwError != 0) {
            Log("[CertVerifyCertificateChainPolicy] Cleared TLS certificate error 0x" + std::to_string(st->dwError) + " -> 0 (SSL Pinning Bypass)");
            st->dwError = 0;
        }
    }
    return TRUE;
}

static LONG WINAPI Hk_WinVerifyTrust(HWND, GUID*, LPVOID) {
    Log("[WinVerifyTrust] -> FORCED ERROR_SUCCESS (0)");
    return 0;
}

// ============================================================================
// 4. JAVA / JVM (sunmscapi.dll), .NET (clr.dll/coreclr.dll), GO & RUST SUPPORT
// ============================================================================
typedef unsigned char jboolean;
typedef jboolean (__stdcall* Java_CSignature_verifySignedHash_t)(void* env, void* clazz, void* alg, void* hash, void* sig, void* pubKey);
static Java_CSignature_verifySignedHash_t orig_JavaVerifySignedHash = nullptr;

static jboolean __stdcall Hk_JavaVerifySignedHash(void*, void*, void*, void*, void*, void*) {
    Log("[JVM:sunmscapi] Java_sun_security_mscapi_CSignature_verifySignedHash -> FORCED JNI_TRUE (1)");
    return 1;
}

// ============================================================================
// 5. UNIVERSAL NON-KEYAUTH GENERIC LICENSE / AUTH LEA BRANCH PATCHER
//    Finds generic license failure strings in ANY C/C++/Rust/Go/Delphi PE binary,
//    traces RIP-relative LEA XRefs in .text, and patches TEST EAX,EAX + JE -> NOP
// ============================================================================
static int PatchUniversalNonKeyAuthBranches() {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (!hExe) return 0;
    auto* base = (uint8_t*)hExe;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;

    static const char* kGenericAuthFailStrings[] = {
        "Invalid license",
        "License expired",
        "Invalid key",
        "Invalid serial",
        "Activation failed",
        "HWID mismatch",
        "Trial expired",
        "Verification failed",
        "Subscription expired",
        "Unauthorized",
        nullptr
    };

    int patchedCount = 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int sIdx = 0; kGenericAuthFailStrings[sIdx]; sIdx++) {
        const char* needle = kGenericAuthFailStrings[sIdx];
        size_t nlen = strlen(needle);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            uint8_t* sStart = base + sec[i].VirtualAddress;
            size_t sLen = sec[i].Misc.VirtualSize;
            const char* hit = memmem_lite((const char*)sStart, sLen, needle, nlen);
            if (!hit) continue;

            uintptr_t strAddr = (uintptr_t)hit;
            for (WORD j = 0; j < nt->FileHeader.NumberOfSections; j++) {
                if (!(sec[j].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                uint8_t* cStart = base + sec[j].VirtualAddress;
                size_t cLen = sec[j].Misc.VirtualSize;
                for (size_t k = 0; k + 7 <= cLen; k++) {
                    if (cStart[k] == 0x48 && cStart[k + 1] == 0x8D && (cStart[k + 2] == 0x0D || cStart[k + 2] == 0x15)) {
                        int32_t disp = *(int32_t*)(cStart + k + 3);
                        uintptr_t target = (uintptr_t)(cStart + k + 7) + disp;
                        if (target == strAddr) {
                            DWORD rva = (DWORD)((uintptr_t)(cStart + k) - (uintptr_t)base);
                            Log(std::string("[UniversalBranchScan] Found LEA XRef to \"") + needle + "\" @ RVA 0x" + std::to_string(rva));
                            size_t lookBack = (k > 48) ? (k - 48) : 0;
                            for (size_t b = lookBack; b + 4 <= k; b++) {
                                if (cStart[b] == 0x85 && cStart[b + 1] == 0xC0 && cStart[b + 2] == 0x74) {
                                    DWORD oldProt = 0;
                                    if (VirtualProtect(cStart + b + 2, 2, PAGE_EXECUTE_READWRITE, &oldProt)) {
                                        cStart[b + 2] = 0x90;
                                        cStart[b + 3] = 0x90;
                                        VirtualProtect(cStart + b + 2, 2, oldProt, &oldProt);
                                        patchedCount++;
                                        Log("[UniversalBranchScan] Patched short JE guarding \"" + std::string(needle) + "\" -> NOP NOP");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return patchedCount;
}

static void DetectAndLogRuntimeStacks() {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (hExe) {
        auto* base = (uint8_t*)hExe;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                size_t imgSz = nt->OptionalHeader.SizeOfImage;
                if (memmem_lite((const char*)base, imgSz, "Go buildinf:", 12) ||
                    memmem_lite((const char*)base, imgSz, "crypto/tls.(*Conn).Read", 23)) {
                    Log("[RuntimeDetect] Go (Golang) binary detected! (crypto/tls + WSARecv/CertVerify hooks active)");
                }
                if (memmem_lite((const char*)base, imgSz, "rust_panic", 10) ||
                    memmem_lite((const char*)base, imgSz, "core::panicking", 15)) {
                    Log("[RuntimeDetect] Rust binary detected! (rustls/ring/native-tls + SChannel/WinHTTP/BCrypt hooks active)");
                }
            }
        }
    }
    if (GetModuleHandleW(L"clr.dll") || GetModuleHandleW(L"coreclr.dll") || GetModuleHandleW(L"mscoree.dll")) {
        Log("[RuntimeDetect] .NET / C# CLR runtime detected! (SslStream/sspicli + HttpClient/WinHTTP + BCrypt hooks active)");
    }
    if (GetModuleHandleW(L"jvm.dll") || GetModuleHandleW(L"java.dll")) {
        Log("[RuntimeDetect] Java JVM runtime detected! (SunMSCAPI + Socket/TLS hooks active)");
    }
}

static void InstallUniversalMultiStackHooks() {
    DetectAndLogRuntimeStacks();

    // 1. WinHTTP (winhttp.dll)
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryW(L"winhttp.dll");
    if (hWinHttp) {
        if (auto p = GetProcAddress(hWinHttp, "WinHttpReadData"))
            MH_CreateHook(p, Hk_WinHttpReadData, (void**)&orig_WinHttpReadData);
        if (auto p = GetProcAddress(hWinHttp, "WinHttpQueryHeaders"))
            MH_CreateHook(p, Hk_WinHttpQueryHeaders, (void**)&orig_WinHttpQueryHeaders);
    }

    // 2. WinINet (wininet.dll)
    HMODULE hWinInet = GetModuleHandleW(L"wininet.dll");
    if (!hWinInet) hWinInet = LoadLibraryW(L"wininet.dll");
    if (hWinInet) {
        if (auto p = GetProcAddress(hWinInet, "InternetReadFile"))
            MH_CreateHook(p, Hk_InternetReadFile, (void**)&orig_InternetReadFile);
        if (auto p = GetProcAddress(hWinInet, "HttpQueryInfoW"))
            MH_CreateHook(p, Hk_HttpQueryInfoW, (void**)&orig_HttpQueryInfoW);
        if (auto p = GetProcAddress(hWinInet, "HttpQueryInfoA"))
            MH_CreateHook(p, Hk_HttpQueryInfoA, (void**)&orig_HttpQueryInfoA);
    }

    // 3. BCrypt (bcrypt.dll) - Custom AES/RSA Decryption & Signature Verification
    HMODULE hBCrypt = GetModuleHandleW(L"bcrypt.dll");
    if (!hBCrypt) hBCrypt = LoadLibraryW(L"bcrypt.dll");
    if (hBCrypt) {
        if (auto p = GetProcAddress(hBCrypt, "BCryptDecrypt"))
            MH_CreateHook(p, Hk_BCryptDecrypt, (void**)&orig_BCryptDecrypt);
    }

    // 4. NCrypt (ncrypt.dll) - Windows CNG Key Storage & Custom Crypto
    HMODULE hNCrypt = GetModuleHandleW(L"ncrypt.dll");
    if (!hNCrypt) hNCrypt = LoadLibraryW(L"ncrypt.dll");
    if (hNCrypt) {
        if (auto p = GetProcAddress(hNCrypt, "NCryptVerifySignature"))
            MH_CreateHook(p, Hk_NCryptVerifySignature, (void**)&orig_NCryptVerifySignature);
        if (auto p = GetProcAddress(hNCrypt, "NCryptDecrypt"))
            MH_CreateHook(p, Hk_NCryptDecrypt, (void**)&orig_NCryptDecrypt);
    }

    // 5. Advapi32 CryptoAPI (CryptVerifySignatureW/A, CryptDecrypt)
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    if (!hAdv) hAdv = LoadLibraryW(L"advapi32.dll");
    if (hAdv) {
        if (auto p = GetProcAddress(hAdv, "CryptVerifySignatureW"))
            MH_CreateHook(p, Hk_CryptVerifySignatureW, (void**)&orig_CryptVerifySignatureW);
        if (auto p = GetProcAddress(hAdv, "CryptVerifySignatureA"))
            MH_CreateHook(p, Hk_CryptVerifySignatureA, (void**)&orig_CryptVerifySignatureA);
        if (auto p = GetProcAddress(hAdv, "CryptDecrypt"))
            MH_CreateHook(p, Hk_CryptDecrypt, (void**)&orig_CryptDecrypt);
    }

    // 6. Crypt32 (CertVerifyCertificateChainPolicy - Universal SSL Pinning Bypass)
    HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
    if (!hCrypt32) hCrypt32 = LoadLibraryW(L"crypt32.dll");
    if (hCrypt32) {
        if (auto p = GetProcAddress(hCrypt32, "CertVerifyCertificateChainPolicy"))
            MH_CreateHook(p, Hk_CertVerifyCertificateChainPolicy, (void**)&orig_CertVerifyCertificateChainPolicy);
    }

    // 7. WinTrust (wintrust.dll - WinVerifyTrust Authenticode/Signature Bypass)
    HMODULE hTrust = GetModuleHandleW(L"wintrust.dll");
    if (!hTrust) hTrust = LoadLibraryW(L"wintrust.dll");
    if (hTrust) {
        if (auto p = GetProcAddress(hTrust, "WinVerifyTrust"))
            MH_CreateHook(p, Hk_WinVerifyTrust, (void**)&orig_WinVerifyTrust);
    }

    // 8. Java SunMSCAPI (sunmscapi.dll) if loaded
    if (HMODULE hMscapi = GetModuleHandleW(L"sunmscapi.dll")) {
        if (auto p = GetProcAddress(hMscapi, "Java_sun_security_mscapi_CSignature_verifySignedHash"))
            MH_CreateHook(p, Hk_JavaVerifySignedHash, (void**)&orig_JavaVerifySignedHash);
    }

    Log("[UniversalMultiStack] Installed WinHTTP, WinINet, BCryptDecrypt, NCrypt, CryptoAPI, CertVerify & WinTrust hooks!");
}
