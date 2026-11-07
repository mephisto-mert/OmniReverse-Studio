// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com

#define LOGGING_ENABLED     1

#define EXPIRY_DAY          20
#define EXPIRY_MONTH        7
#define EXPIRY_YEAR         0


#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <sspi.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <stdlib.h>
#include <MinHook.h>
#include "ed25519_sign.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

static HMODULE  g_hMod = nullptr;
static PVOID    g_vehHandle = nullptr;
static char     g_logPath[MAX_PATH] = {};
static char     g_dumpPath[MAX_PATH] = {};
static std::mutex g_logMtx;

// RFC 8032 test vector keypair — used to re-sign rewritten responses so the app's ed25519 verify passes
static const uint8_t FAKE_SK[64] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60,
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
};
static const char FAKE_PK_HEX[65] =
"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

static std::string BytesToHex(const uint8_t* b, size_t n) {
    static const char h[] = "0123456789abcdef";
    std::string s(n * 2, '\0');
    for (size_t i = 0; i < n; i++) { s[2 * i] = h[b[i] >> 4]; s[2 * i + 1] = h[b[i] & 0xf]; }
    return s;
}

static void InitLog(HMODULE hMod) {
    g_hMod = hMod;
    wchar_t p[MAX_PATH] = {};
    GetModuleFileNameW(hMod, p, MAX_PATH);
    wchar_t* last = wcsrchr(p, L'\\');
    if (last) *(last + 1) = L'\0';
    wchar_t wp[MAX_PATH];
    _snwprintf_s(wp, MAX_PATH, _TRUNCATE, L"%skeyauth_patcher_log.txt", p);
    WideCharToMultiByte(CP_ACP, 0, wp, -1, g_logPath, MAX_PATH, nullptr, nullptr);
    _snwprintf_s(wp, MAX_PATH, _TRUNCATE, L"%skeyauth_response_dump.txt", p);
    WideCharToMultiByte(CP_ACP, 0, wp, -1, g_dumpPath, MAX_PATH, nullptr, nullptr);
#if LOGGING_ENABLED
    FILE* f = nullptr;
    fopen_s(&f, g_logPath, "w"); if (f) fclose(f);
    fopen_s(&f, g_dumpPath, "w"); if (f) fclose(f);
#endif
}

static void DumpResponse(int callNum, const char* buf, ULONG len) {
#if LOGGING_ENABLED
    if (!buf || len == 0 || !g_dumpPath[0]) return;
    std::lock_guard<std::mutex> lk(g_logMtx);
    FILE* f = nullptr;
    fopen_s(&f, g_dumpPath, "a");
    if (!f) return;
    fprintf(f, "\n=== DecryptMessage #%d (len=%u) ===\n", callNum, (unsigned)len);
    fwrite(buf, 1, len, f);
    fprintf(f, "\n");
    fclose(f);
#else
    (void)callNum; (void)buf; (void)len;
#endif
}

static void Log(const std::string& msg) {
#if LOGGING_ENABLED
    if (!g_logPath[0]) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    char hdr[64];
    _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
        "[%02d:%02d:%02d.%03d T%-5lu] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        (unsigned long)GetCurrentThreadId());
    std::lock_guard<std::mutex> lk(g_logMtx);
    FILE* f = nullptr;
    fopen_s(&f, g_logPath, "a");
    if (f) {
        fwrite(hdr, 1, strlen(hdr), f);
        fwrite(msg.c_str(), 1, msg.size(), f);
        fwrite("\n", 1, 1, f);
        fclose(f);
    }
#else
    (void)msg;
#endif
}

static decltype(&VirtualProtect) real_VirtualProtect = VirtualProtect;

// patches the EXE's own import table — faster than MH_CreateHook and survives VMP section relocs
static void* IATHook(const char* moduleName, const char* funcName, void* newFunc) {
    __try {
        HMODULE hExe = GetModuleHandleW(NULL);
        auto* dos = (IMAGE_DOS_HEADER*)hExe;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
        auto& imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!imp.VirtualAddress || imp.Size == 0) return nullptr;

        BYTE* base = (BYTE*)hExe;
        SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;

        auto inBounds = [&](const void* p, size_t sz = 1) -> bool {
            return p && (BYTE*)p >= base && (BYTE*)p + sz <= base + imgSize;
            };

        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp.VirtualAddress);
        for (int di = 0; di < 256 && inBounds(desc) && desc->Name; di++, desc++) {
            if (!inBounds(base + desc->Name)) continue;
            const char* name = (const char*)(base + desc->Name);
            if (_stricmp(name, moduleName) != 0) continue;
            if (!desc->FirstThunk || !desc->OriginalFirstThunk) continue;

            auto* thunk = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            auto* orig = (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk);
            for (; inBounds(thunk) && inBounds(orig) && thunk->u1.Function; thunk++, orig++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
                if (!inBounds(base + orig->u1.AddressOfData)) continue;
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
                if (!inBounds(ibn->Name)) continue;
                if (_stricmp((char*)ibn->Name, funcName) != 0) continue;

                void* old = (void*)thunk->u1.Function;
                DWORD old_prot;
                real_VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old_prot);
                thunk->u1.Function = (ULONG_PTR)newFunc;
                real_VirtualProtect(&thunk->u1.Function, sizeof(void*), old_prot, &old_prot);
                return old;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return nullptr;
}

static std::string JStr(const std::string& j, const std::string& key) {
    std::string s = "\"" + key + "\":\"";
    size_t p = j.find(s);
    if (p == std::string::npos) return "";
    p += s.size();
    size_t e = j.find('"', p);
    return e == std::string::npos ? "" : j.substr(p, e - p);
}

static std::string BuildSuccessJSON(const std::string& nonce,
    const std::string& ownerid = "") {
    return std::string(
        "{\"success\":true,\"code\":68,\"message\":\"Logged in!\","
        "\"info\":{\"username\":\"Kariexscontxct\","
        "\"subscriptions\":[{\"subscription\":\"default\","
        "\"key\":\"licensed\","
        "\"expiry\":\"9999999999\","
        "\"timeleft\":9999999999}],"
        "\"ip\":\"\",\"hwid\":\"\","
        "\"createdate\":\"1700000000\",\"lastlogin\":\"1700000000\"},"
        "\"nonce\":\"") + nonce + "\","
        "\"ownerid\":\"" + ownerid + "\"}";
}

static std::string BuildFakeHTTPResponse(const std::string& nonce,
    const std::string& ownerid = "",
    const std::string& sig = "",
    const std::string& ts = "") {
    const std::string body = BuildSuccessJSON(nonce, ownerid);
    std::string r = "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n";
    if (!sig.empty()) r += "x-signature-ed25519: " + sig + "\r\n";
    if (!ts.empty())  r += "x-signature-timestamp: " + ts + "\r\n";
    r += "\r\n" + body;
    return r;
}

static std::string ExtractJsonStr(const char* buf, size_t len, const char* key) {
    std::string needle = std::string("\"") + key + "\":\"";
    size_t nl = needle.size();
    for (size_t i = 0; i + nl + 1 <= len; i++) {
        if (memcmp(buf + i, needle.c_str(), nl) != 0) continue;
        size_t start = i + nl, end = start;
        while (end < len && buf[end] != '"' && (end - start) < 256) end++;
        if (end < len && buf[end] == '"') return std::string(buf + start, end - start);
    }
    return "";
}
static std::string ExtractNonce(const char* buf, size_t len) {
    return ExtractJsonStr(buf, len, "nonce");
}
static std::string ExtractOwnerid(const char* buf, size_t len) {
    return ExtractJsonStr(buf, len, "ownerid");
}

static bool InplaceFlipSuccess(BYTE* base, SIZE_T start, SIZE_T end) {
    SIZE_T len = end - start;
    char* buf = (char*)(base + start);
    bool patched = false;
    const char* falseStr = "\"success\":false";
    const char* trueStr = "\"success\":true ";
    for (SIZE_T i = 0; i + 15 < len; i++) {
        if (memcmp(buf + i, falseStr, 15) == 0) {
            memcpy(buf + i, trueStr, 15);
            patched = true;
        }
    }
    return patched;
}

struct MsvcString {
    union { char* ptr; char sso[16]; };
    size_t size;
    size_t cap;
};

static std::set<BYTE*> g_rewrittenBodies;
static std::mutex g_rewriteMutex;

// when the JSON body lives in a heap std::string, swap its pointer/size so the app sees the fake body
static bool RewriteStringOwners(BYTE* bodyAddr, size_t origLen, const std::string& newContent) {
    {
        std::lock_guard<std::mutex> lock(g_rewriteMutex);
        if (g_rewrittenBodies.count(bodyAddr)) return false;
        g_rewrittenBodies.insert(bodyAddr);
    }

    HANDLE hProc = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi = {};
    BYTE* addr = nullptr;
    int rewrites = 0;
    size_t newLen = newContent.size();

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize >= sizeof(MsvcString))
        {
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T sz = mbi.RegionSize;
            for (SIZE_T k = 0; k + sizeof(MsvcString) <= sz; k += 8) {
                MsvcString* ms = (MsvcString*)(base + k);
                if (ms->ptr == (char*)bodyAddr && ms->cap >= origLen && ms->size == origLen) {
                    char* nb = (char*)malloc(newLen + 1);
                    if (nb) {
                        memcpy(nb, newContent.c_str(), newLen + 1);
                        ms->ptr = nb;
                        ms->size = newLen;
                        ms->cap = newLen;
                        rewrites++;
                    }
                }
            }
        }
        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    if (rewrites > 0)
        Log("  RewriteString: " + std::to_string(rewrites) + " owners, " +
            std::to_string(origLen) + "->" + std::to_string(newLen));
    return rewrites > 0;
}

static bool FullPatch(BYTE* base, SIZE_T start, SIZE_T end) {
    size_t origLen = end - start;
    std::string body((char*)base + start, origLen);
    std::string nonce = ExtractNonce(body.data(), body.size());
    if (nonce.empty()) return false;
    std::string ownerid = ExtractOwnerid(body.data(), body.size());
    std::string success = BuildSuccessJSON(nonce, ownerid);

    if (success.size() <= origLen) {
        char* dst = (char*)base + start;
        memcpy(dst, success.c_str(), success.size());
        memset(dst + success.size(), ' ', origLen - success.size());
        Log("  FullPatch in-place: " + std::to_string(success.size()) + "/" + std::to_string(origLen));
        return true;
    }
    return RewriteStringOwners(base + start, origLen, success);
}

static std::set<std::string> g_patchedNonces;
static std::mutex             g_patchedNoncesMtx;

static void ScanAndPatchHeap() {
    HANDLE hProc = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi = {};
    BYTE* addr = nullptr;
    const char* needle = "\"success\":false";
    const size_t nlen = strlen(needle);
    int found = 0, patched = 0, skipped = 0;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize >= nlen && mbi.RegionSize <= 0x200000)
        {
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T sz = mbi.RegionSize;
            for (SIZE_T i = 0; i + nlen < sz; i++) {
                if (memcmp(base + i, needle, nlen) != 0) continue;
                SIZE_T start = i;
                while (start > 0 && base[start] != '{') start--;
                if (base[start] != '{') { i += nlen; continue; }
                SIZE_T end = i + nlen;
                while (end < sz && base[end] != '\0' && (end - start) < 4096) end++;
                if (end >= sz || end <= start) { i += nlen; continue; }
                std::string preview((char*)base + start, end - start);
                if (preview.find("\"nonce\"") == std::string::npos) { i += nlen; continue; }
                found++;
                std::string nonce = ExtractNonce(preview.data(), preview.size());
                {
                    std::lock_guard<std::mutex> lk(g_patchedNoncesMtx);
                    if (!nonce.empty() && g_patchedNonces.count(nonce)) { skipped++; i = end; continue; }
                }
                bool ok = FullPatch(base, start, end);
                if (!ok) ok = InplaceFlipSuccess(base, start, end);
                if (ok) {
                    patched++;
                    if (!nonce.empty()) {
                        std::lock_guard<std::mutex> lk(g_patchedNoncesMtx);
                        g_patchedNonces.insert(nonce);
                    }
                }
                i = end;
            }
        }
        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    if (found > 0)
        Log("Heap scan: " + std::to_string(found) + " hit(s), " +
            std::to_string(patched) + " patched, " +
            std::to_string(skipped) + " already done");
}


struct PESection { BYTE* base; SIZE_T size; std::string name; };

static std::vector<PESection> EnumSections() {
    std::vector<PESection> out;
    HMODULE hExe = GetModuleHandleW(NULL);
    auto* dos = (IMAGE_DOS_HEADER*)hExe;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        out.push_back({ (BYTE*)hExe + sec->VirtualAddress, sec->Misc.VirtualSize, nm });
    }
    return out;
}

static std::vector<BYTE*> FindStringRefs(const char* str) {
    std::vector<BYTE*> hits;
    size_t slen = strlen(str);
    for (auto& s : EnumSections()) {
        if (s.size < slen) continue;
        for (SIZE_T i = 0; i + slen + 1 <= s.size; i++) {
            if (memcmp(s.base + i, str, slen) == 0 && s.base[i + slen] == 0)
                hits.push_back(s.base + i);
        }
    }
    return hits;
}

static std::vector<BYTE*> FindLeaToString(BYTE* stringAddr) {
    std::vector<BYTE*> hits;
    for (auto& s : EnumSections()) {
        if (s.size < 7) continue;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(s.base, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
        DWORD prot = mbi.Protect & 0xFF;
        if (!(prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) continue;
        for (SIZE_T i = 0; i + 7 <= s.size; i++) {
            BYTE* p = s.base + i;
            if (p[0] != 0x48 || p[1] != 0x8D) continue;
            if (p[2] != 0x15 && p[2] != 0x0D) continue;
            INT32 disp = *(INT32*)(p + 3);
            if (p + 7 + disp == stringAddr) hits.push_back(p);
        }
    }
    return hits;
}

static bool PatchJeBeforeLea(BYTE* leaAddr, BYTE** outCallTarget = nullptr) {
    BYTE* end = leaAddr;
    HMODULE hExe = GetModuleHandleW(NULL);
    auto* dosHdr = (IMAGE_DOS_HEADER*)hExe;
    auto* ntHdr = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dosHdr->e_lfanew);

    BYTE* secFloor = (BYTE*)hExe;
    {
        auto* sChk = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD si = 0; si < ntHdr->FileHeader.NumberOfSections; si++, sChk++) {
            BYTE* sb = (BYTE*)hExe + sChk->VirtualAddress;
            if (leaAddr >= sb && leaAddr < sb + sChk->Misc.VirtualSize) {
                secFloor = sb;
                break;
            }
        }
    }
    BYTE* start = (leaAddr > secFloor + 64) ? (leaAddr - 64) : secFloor;

    auto extractCallTarget = [&](BYTE* testEax) -> BYTE* {
        if (testEax < secFloor + 5) return nullptr;
        BYTE* callInstr = testEax - 5;
        if (callInstr[0] != 0xE8) return nullptr;
        int32_t rel = *(int32_t*)(callInstr + 1);
        BYTE* target = callInstr + 5 + rel;
        auto* sec = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, sec++) {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            BYTE* sBase = (BYTE*)hExe + sec->VirtualAddress;
            if (target >= sBase && target < sBase + sec->Misc.VirtualSize) return target;
        }
        return nullptr;
        };

    auto patchBytes = [](void* addr, const BYTE* bytes, SIZE_T n) -> bool {
        SIZE_T wr = 0;
        if (WriteProcessMemory(GetCurrentProcess(), addr, bytes, n, &wr) && wr == n)
            return true;
        DWORD op;
        if (!real_VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &op)) return false;
        memcpy(addr, bytes, n);
        real_VirtualProtect(addr, n, op, &op);
        return true;
        };

    for (BYTE* p = start; p < end; p++) {
        if (p[0] == 0x85 && p[1] == 0xC0 && p[2] == 0x74) {
            INT8 disp = (INT8)p[3];
            BYTE* target = p + 4 + disp;
            if (target > leaAddr && target < leaAddr + 0x100) {
                BYTE b = 0xEB;
                if (patchBytes(p + 2, &b, 1)) {
                    Log("PatchJe: 74->EB at 0x" + std::to_string((uintptr_t)(p + 2)));
                    if (outCallTarget) *outCallTarget = extractCallTarget(p);
                    return true;
                }
            }
        }
        if (p[0] == 0x85 && p[1] == 0xC0 && p[2] == 0x0F && p[3] == 0x84 && (p + 8 <= end)) {
            INT32 disp = *(INT32*)(p + 4);
            BYTE* target = p + 8 + disp;
            if (target > leaAddr && target < leaAddr + 0x1000) {
                BYTE bs[] = { 0x90, 0xE9 };
                if (patchBytes(p + 2, bs, 2)) {
                    Log("PatchJe: 0F84->90E9 at 0x" + std::to_string((uintptr_t)(p + 2)));
                    if (outCallTarget) *outCallTarget = extractCallTarget(p);
                    return true;
                }
            }
        }
        if (p[0] == 0x0F && p[1] == 0x85 && (p + 6 <= end)) {
            INT32 disp = *(INT32*)(p + 2);
            BYTE* target = p + 6 + disp;
            if (target >= leaAddr - 16 && target <= leaAddr + 16) {
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                if (patchBytes(p, nops, 6)) {
                    Log("PatchJe: NOP'd jne rel32 at 0x" + std::to_string((uintptr_t)p));
                    return true;
                }
            }
        }
        if (p[0] == 0x75 && (p + 2 <= end)) {
            INT8 disp = (INT8)p[1];
            BYTE* target = p + 2 + disp;
            if (target >= leaAddr - 16 && target <= leaAddr + 16) {
                BYTE nops[] = { 0x90, 0x90 };
                if (patchBytes(p, nops, 2)) {
                    Log("PatchJe: NOP'd jne short at 0x" + std::to_string((uintptr_t)p));
                    return true;
                }
            }
        }
    }
    return false;
}

static bool IsVmpProtected() {
    HMODULE hExe = GetModuleHandleW(NULL);
    auto* dos = (IMAGE_DOS_HEADER*)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char name[9] = {};
        memcpy(name, sec->Name, 8);
        if (_strnicmp(name, ".vmp", 4) == 0) return true;
    }
    return false;
}

static int PatchSignatureVerify() {
    const char* errStrs[] = {
        "Signature verification failed (invalid signature)",
        "Signature verification failed.",
        "Signature verification failed (invalid public key)",
        "Signature verification failed (invalid signature format)",
        "Signature verification failed (sig length)",
        nullptr
    };

    int patched = 0;
    BYTE* verifyFunc = nullptr;

    for (int k = 0; errStrs[k]; k++) {
        auto refs = FindStringRefs(errStrs[k]);
        if (refs.empty()) continue;
        Log("sig err str \"" + std::string(errStrs[k]) + "\" (" + std::to_string(refs.size()) + ")");
        for (BYTE* strAddr : refs) {
            auto leas = FindLeaToString(strAddr);
            Log("  -> " + std::to_string(leas.size()) + " lea refs");
            for (BYTE* lea : leas) {
                BYTE* callTarget = nullptr;
                if (PatchJeBeforeLea(lea, &callTarget)) {
                    patched++;
                    if (!verifyFunc && callTarget) {
                        BYTE xorRet[] = { 0x33, 0xC0, 0xC3 };
                        SIZE_T wr = 0;
                        bool ok = WriteProcessMemory(GetCurrentProcess(), callTarget, xorRet, 3, &wr) && wr == 3;
                        if (!ok) {
                            DWORD op;
                            if (real_VirtualProtect(callTarget, 4, PAGE_EXECUTE_READWRITE, &op)) {
                                callTarget[0] = 0x33; callTarget[1] = 0xC0; callTarget[2] = 0xC3;
                                real_VirtualProtect(callTarget, 4, op, &op);
                                ok = true;
                            }
                        }
                        if (ok) {
                            verifyFunc = callTarget;
                            uintptr_t rva = (uintptr_t)callTarget - (uintptr_t)GetModuleHandleW(NULL);
                            char hexBuf[32]; snprintf(hexBuf, sizeof(hexBuf), "%llx", (unsigned long long)rva);
                            Log("ed25519 func patched @ 0x" + std::string(hexBuf));
                            patched++;
                        }
                        else {
                            Log("ed25519 patch failed");
                        }
                    }
                }
            }
        }
    }
    Log("sig bypass: " + std::to_string(patched) + " patches");
    return patched;
}

typedef int (*sodium_verify_t)(const unsigned char*, const unsigned char*,
    unsigned long long, const unsigned char*);
static sodium_verify_t orig_SodiumVerify = nullptr;
static BYTE* g_sodiumVerifyAddr = nullptr;

static int Hk_SodiumVerify(const unsigned char* sig, const unsigned char* m,
    unsigned long long mlen, const unsigned char* pk) {
    Log("sodium verify mlen=" + std::to_string((long long)mlen));
    return 0;
}

static DWORD64 g_hwbpTarget = 0;
static DWORD64 g_hwbpTarget2 = 0;

// existing threads don't inherit DR regs when we set them on our own thread — must push to each one manually
static void SetHWBPOnAllThreads() {
    DWORD pid = GetCurrentProcessId();
    DWORD myTid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    int count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == myTid) continue;
            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (!h) continue;
            SuspendThread(h);
            CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h, &ctx)) {
                ctx.Dr7 &= ~0x000F000FULL;
                if (g_hwbpTarget) { ctx.Dr0 = g_hwbpTarget;  ctx.Dr7 |= 0x1ULL; }
                if (g_hwbpTarget2) { ctx.Dr1 = g_hwbpTarget2; ctx.Dr7 |= 0x4ULL; }
                SetThreadContext(h, &ctx);
                count++;
            }
            ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    Log("hwbp: set on " + std::to_string(count) + " threads");
}

static void SetHWBPOnThread(HANDLE hThread) {
    if (!g_hwbpTarget && !g_hwbpTarget2) return;
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return;
    ctx.Dr7 &= ~0x000F000FULL;
    if (g_hwbpTarget) {
        ctx.Dr0 = g_hwbpTarget;
        ctx.Dr7 |= 0x00000001ULL;
    }
    if (g_hwbpTarget2) {
        ctx.Dr1 = g_hwbpTarget2;
        ctx.Dr7 |= 0x00000004ULL;
    }
    SetThreadContext(hThread, &ctx);
}

// DR0 = sodium ed25519_verify entry, DR1 = sig verify func entry
// we manually pop the return address and set rax so the real function never runs
static LONG CALLBACK VEH_SodiumHook(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* ctx = ep->ContextRecord;

    if ((ctx->Dr6 & 1) && g_hwbpTarget && ctx->Rip == g_hwbpTarget) {
        ctx->Dr6 &= ~1ULL;
        Log("dr0: sodium -> 0");
        ctx->Rax = 0;
        ctx->Rip = *(DWORD64*)ctx->Rsp;
        ctx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if ((ctx->Dr6 & 2) && g_hwbpTarget2 && ctx->Rip == g_hwbpTarget2) {
        ctx->Dr6 &= ~2ULL;
        Log("dr1: sigfunc -> 0xa58f");
        ctx->Rax = 0xa58f;
        ctx->Rip = *(DWORD64*)ctx->Rsp;
        ctx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// tries 3 strategies in order: direct sodium prologue scan -> wrapper pattern -> CALL+TEST fallback
// MinHook only for non-VMP; VMP targets use HWBP instead (VMP hashes prologue bytes)
static bool HookVerifyDetached() {
    HMODULE hExe = GetModuleHandleW(NULL);
    auto* dosHdr = (IMAGE_DOS_HEADER*)hExe;
    auto* ntHdr = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dosHdr->e_lfanew);

    auto tryHook = [&](BYTE* target, const char* method) -> bool {
        uintptr_t rva = (uintptr_t)target - (uintptr_t)hExe;
        char buf[32]; snprintf(buf, sizeof(buf), "%llx", (unsigned long long)rva);
        Log("sodium hook [" + std::string(method) + "] 0x" + std::string(buf));
        MH_STATUS st = MH_CreateHook(target, Hk_SodiumVerify, (void**)&orig_SodiumVerify);
        if (st == MH_OK || st == MH_ERROR_ALREADY_CREATED) {
            g_sodiumVerifyAddr = target;
            Log("minhook ok");
            return true;
        }
        Log("minhook fail st=" + std::to_string((int)st));
        return false;
        };

    auto isVmpSection = [&](BYTE* addr) -> bool {
        auto* s = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, s++) {
            char nm[9] = {}; memcpy(nm, s->Name, 8);
            if (_strnicmp(nm, ".vmp", 4) != 0) continue;
            BYTE* sb = (BYTE*)hExe + s->VirtualAddress;
            if (addr >= sb && addr < sb + s->Misc.VirtualSize) return true;
        }
        return false;
        };

    {
        static const BYTE kLibSodiumProl[] = {
            0x40,0x53,0x55,0x56,0x57,0x41,0x56,
            0x48,0x81,0xEC,0x80,0x02,0x00,0x00
        };
        bool hookedAny = false;
        int hookCount = 0;
        auto* secP = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD ip = 0; ip < ntHdr->FileHeader.NumberOfSections; ip++, secP++) {
            if (!(secP->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            char nmP[9] = {}; memcpy(nmP, secP->Name, 8);
            BYTE* baseP = (BYTE*)hExe + secP->VirtualAddress;
            SIZE_T szP = secP->Misc.VirtualSize;
            for (SIZE_T jP = 0; jP + sizeof(kLibSodiumProl) <= szP; jP++) {
                if (memcmp(baseP + jP, kLibSodiumProl, sizeof(kLibSodiumProl)) != 0) continue;
                if (hookCount >= 8) break;
                uintptr_t rva2 = (uintptr_t)(baseP + jP) - (uintptr_t)hExe;
                char rbuf[32]; snprintf(rbuf, sizeof(rbuf), "%llx", (unsigned long long)rva2);
                Log("sodium candidate [" + std::string(nmP) + "] 0x" + std::string(rbuf));
                if (tryHook(baseP + jP, "priority0-libsodium")) {
                    hookedAny = true;
                    hookCount++;
                }
            }
        }
        if (hookedAny) {
            Log("sodium: " + std::to_string(hookCount) + " hook(s) ok");
            return true;
        }
        Log("sodium prologue not found, trying wrapper");
    }

    static const BYTE kHead[] = {
        0x48, 0x83, 0xEC, 0x38,
        0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
        0xE8
    };
    static const BYTE kTail[] = { 0x48, 0x83, 0xC4, 0x38, 0xC3 };
    constexpr SIZE_T kTotal = sizeof(kHead) + 4 + sizeof(kTail);

    auto* sec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        if (_strnicmp(nm, ".vmp", 4) == 0) continue;
        BYTE* base = (BYTE*)hExe + sec->VirtualAddress;
        SIZE_T sz = sec->Misc.VirtualSize;
        if (sz < kTotal) continue;
        for (SIZE_T j = 0; j + kTotal <= sz; j++) {
            if (memcmp(base + j, kHead, sizeof(kHead)) != 0) continue;
            if (memcmp(base + j + sizeof(kHead) + 4, kTail, sizeof(kTail)) != 0) continue;
            {
                static const BYTE kSodiumProl[] = {
                    0x40,0x53,0x55,0x56,0x57,0x41,0x56,
                    0x48,0x81,0xEC,0x80,0x02,0x00,0x00
                };
                int32_t callRel = *(int32_t*)(base + j + sizeof(kHead));
                BYTE* callTarget = base + j + sizeof(kHead) + 4 + callRel;
                bool    isSodium = false;
                auto* chkS = IMAGE_FIRST_SECTION(ntHdr);
                for (WORD ci = 0; ci < ntHdr->FileHeader.NumberOfSections && !isSodium; ci++, chkS++) {
                    if (!(chkS->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                    BYTE* sb = (BYTE*)hExe + chkS->VirtualAddress;
                    if (callTarget >= sb && callTarget < sb + chkS->Misc.VirtualSize &&
                        memcmp(callTarget, kSodiumProl, sizeof(kSodiumProl)) == 0)
                        isSodium = true;
                }
                if (!isSodium) {
                    char r[32]; snprintf(r, sizeof(r), "%llx",
                        (unsigned long long)((uintptr_t)(base + j) - (uintptr_t)hExe));
                    Log("wrapper 0x" + std::string(r) + " skip (not sodium)");
                    continue;
                }
            }
            if (tryHook(base + j, "wrapper")) return true;
        }
    }

    Log("wrapper not found, trying call+test");
    const char* errStrs[] = {
        "Signature verification failed (invalid signature)",
        "Signature verification failed.",
        nullptr
    };
    for (int k = 0; errStrs[k]; k++) {
        for (BYTE* strAddr : FindStringRefs(errStrs[k])) {
            for (BYTE* lea : FindLeaToString(strAddr)) {
                if (isVmpSection(lea)) {
                    Log("lea in .vmp skip");
                    continue;
                }
                BYTE* secFloor2 = (BYTE*)hExe;
                {
                    auto* sFloor = IMAGE_FIRST_SECTION(ntHdr);
                    for (WORD fi = 0; fi < ntHdr->FileHeader.NumberOfSections; fi++, sFloor++) {
                        BYTE* sfb = (BYTE*)hExe + sFloor->VirtualAddress;
                        if (lea >= sfb && lea < sfb + sFloor->Misc.VirtualSize) {
                            secFloor2 = sfb;
                            break;
                        }
                    }
                }
                BYTE* scanEnd = lea;
                BYTE* scanStart = (lea > secFloor2 + 512) ? (lea - 512) : secFloor2;
                if (scanEnd < scanStart + 7) continue;
                for (BYTE* p = scanEnd - 7; p >= scanStart; p--) {
                    if (p[0] != 0xE8) continue;
                    if (p[5] != 0x85 || p[6] != 0xC0) continue;
                    int32_t rel = *(int32_t*)(p + 1);
                    BYTE* target = p + 5 + rel;
                    auto* s2 = IMAGE_FIRST_SECTION(ntHdr);
                    bool valid = false;
                    for (WORD ii = 0; ii < ntHdr->FileHeader.NumberOfSections; ii++, s2++) {
                        if (!(s2->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                        BYTE* sb = (BYTE*)hExe + s2->VirtualAddress;
                        if (target >= sb && target < sb + s2->Misc.VirtualSize) { valid = true; break; }
                    }
                    if (!valid) continue;
                    if (tryHook(target, "CALL+TEST")) return true;
                }
            }
        }
    }
    Log("trying direct sodium hook");
    {
        static const BYTE kSodiumProlDirect[] = {
            0x40,0x53,0x55,0x56,0x57,0x41,0x56,
            0x48,0x81,0xEC,0x80,0x02,0x00,0x00
        };
        auto* secD = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, secD++) {
            if (!(secD->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            char nm2[9] = {}; memcpy(nm2, secD->Name, 8);
            if (_strnicmp(nm2, ".vmp", 4) == 0) continue;
            BYTE* b2 = (BYTE*)hExe + secD->VirtualAddress;
            SIZE_T sz2 = secD->Misc.VirtualSize;
            for (SIZE_T j2 = 0; j2 + sizeof(kSodiumProlDirect) <= sz2; j2++) {
                if (memcmp(b2 + j2, kSodiumProlDirect, sizeof(kSodiumProlDirect)) != 0) continue;
                if (tryHook(b2 + j2, "direct-libsodium")) return true;
            }
        }
    }
    Log("sodium: all approaches failed");
    return false;
}


static bool HookSigVerifyFunc() {
    HMODULE hExe = GetModuleHandleW(NULL);
    auto* dos = (IMAGE_DOS_HEADER*)hExe;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);

    static const BYTE kPrologue[] = {
        0x40, 0x53,
        0x56,
        0x57,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
        0x48, 0x81, 0xEC, 0x20, 0x01, 0x00, 0x00
    };
    static const BYTE kPostCookie[] = {
        0x48, 0x33, 0xC4,
        0x48, 0x89, 0x84, 0x24, 0x10, 0x01, 0x00, 0x00,
        0x4D, 0x8B, 0xF0,
        0x48, 0x8B, 0xDA,
        0x48, 0x8B, 0xF1
    };
    constexpr SIZE_T kCookieSkip = 7;
    constexpr SIZE_T kTotalMin = sizeof(kPrologue) + kCookieSkip + sizeof(kPostCookie);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        if (_strnicmp(nm, ".vmp", 4) == 0) continue;
        BYTE* base = (BYTE*)hExe + sec->VirtualAddress;
        SIZE_T sz = sec->Misc.VirtualSize;
        if (sz < kTotalMin) continue;

        for (SIZE_T j = 0; j + kTotalMin <= sz; j++) {
            if (memcmp(base + j, kPrologue, sizeof(kPrologue)) != 0) continue;
            if (memcmp(base + j + sizeof(kPrologue) + kCookieSkip,
                kPostCookie, sizeof(kPostCookie)) != 0) continue;

            BYTE* target = base + j;
            uintptr_t rva = (uintptr_t)target - (uintptr_t)hExe;
            char hexbuf[32]; snprintf(hexbuf, sizeof(hexbuf), "%llx", (unsigned long long)rva);
            Log("sigfunc @ 0x" + std::string(hexbuf) + " [" + std::string(nm) + "]");

            g_hwbpTarget2 = (DWORD64)target;
            Log("dr1 set (sigfunc)");
            return true;
        }
    }
    Log("sigfunc pattern not found");
    return false;
}

typedef void* (*KeyGetter_t)(void*);
static KeyGetter_t orig_key_getter = nullptr;
static bool g_keyGetterHooked = false;

static void* Hk_KeyGetter(void* str_out) {
    void* ret = orig_key_getter(str_out);
    if (str_out) {
        char* pbuf = *(char**)str_out;
        if (pbuf) {
            memcpy(pbuf, FAKE_PK_HEX, 64);
            Log("pubkey replaced");
        }
    }
    return ret;
}

static bool HookPubkeyGetter() {
    Log("pubkey getter disabled");
    return false;
}

static decltype(&MapViewOfFile)              orig_MapViewOfFile = nullptr;
static decltype(&CreateFileMappingW)         orig_CreateFileMappingW = nullptr;
static decltype(&CreateFileW)                orig_CreateFileW = nullptr;
static decltype(&UnmapViewOfFile)            orig_UnmapViewOfFile = nullptr;
static decltype(&QueryFullProcessImageNameW) orig_QueryFullProcessImageNameW = nullptr;
static decltype(&VirtualProtect)             orig_VirtualProtect = nullptr;
static HANDLE g_exeMapping = NULL;
static HANDLE g_exeFile = INVALID_HANDLE_VALUE;
static volatile LONG g_crcCount = 0;

static LPVOID WINAPI Hk_MapViewOfFile(HANDLE hMap, DWORD access, DWORD offHi, DWORD offLo, SIZE_T sz) {
    LPVOID ret = orig_MapViewOfFile(hMap, access, offHi, offLo, sz);
    if (hMap == g_exeMapping && g_exeMapping && ret && offHi == 0 && offLo == 0) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(ret, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.RegionSize > sizeof(IMAGE_DOS_HEADER)) {
            HMODULE hExe = GetModuleHandleW(NULL);
            auto* dos = (IMAGE_DOS_HEADER*)hExe;
            auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
            SIZE_T imgSz = nt->OptionalHeader.SizeOfImage;
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
                if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                ULONG cpSz = sec->SizeOfRawData < sec->Misc.VirtualSize
                    ? sec->SizeOfRawData : sec->Misc.VirtualSize;
                if (cpSz == 0) continue;
                if ((SIZE_T)sec->PointerToRawData + cpSz > mbi.RegionSize) continue;
                if ((SIZE_T)sec->VirtualAddress + cpSz > imgSz) continue;
                BYTE* memSec = (BYTE*)hExe + sec->VirtualAddress;
                BYTE* fileSec = (BYTE*)ret + sec->PointerToRawData;
                DWORD oldProt = 0;
                if (orig_VirtualProtect && orig_VirtualProtect(fileSec, cpSz, PAGE_WRITECOPY, &oldProt)) {
                    memcpy(fileSec, memSec, cpSz);
                    orig_VirtualProtect(fileSec, cpSz, oldProt, &oldProt);
                }
            }
            if (g_crcCount % 50 == 1)
                Log("mapview: .text synced #" + std::to_string(g_crcCount));
        }
    }
    return ret;
}

static HANDLE WINAPI Hk_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES sa,
    DWORD prot, DWORD maxHi, DWORD maxLo, LPCWSTR name) {
    HANDLE ret = orig_CreateFileMappingW(hFile, sa, prot, maxHi, maxLo, name);
    if (hFile == g_exeFile && g_exeFile != INVALID_HANDLE_VALUE && ret)
        g_exeMapping = ret;
    return ret;
}

static HANDLE WINAPI Hk_CreateFileW(LPCWSTR path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    HANDLE ret = orig_CreateFileW(path, access, share, sa, disp, flags, tmpl);
    if (ret != INVALID_HANDLE_VALUE && access == GENERIC_READ && path) {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(NULL, self, MAX_PATH);
        if (_wcsicmp(path, self) == 0) {
            g_exeFile = ret;
            if (g_crcCount % 50 == 1)
                Log("createfile: exe tracked #" + std::to_string(g_crcCount));
        }
    }
    return ret;
}

static BOOL WINAPI Hk_UnmapViewOfFile(LPCVOID base) {
    g_exeMapping = NULL;
    g_exeFile = INVALID_HANDLE_VALUE;
    return orig_UnmapViewOfFile(base);
}

static BOOL WINAPI Hk_QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, PWSTR lpExeName, PDWORD lpdwSize) {
    BOOL ret = orig_QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
    if (hProcess == GetCurrentProcess() && dwFlags == 0) {
        LONG n = InterlockedIncrement(&g_crcCount);
        if (n % 50 == 1) {
            char name[MAX_PATH * 2] = {};
            if (ret && lpExeName)
                WideCharToMultiByte(CP_ACP, 0, lpExeName, -1, name, sizeof(name) - 1, nullptr, nullptr);
            Log("qfpin #" + std::to_string(n) + " " + std::string(name));
        }
    }
    return ret;
}

static BOOL WINAPI Hk_VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProt, PDWORD oldProt) {
    if (newProt == PAGE_EXECUTE_READWRITE || newProt == 0x40) {
        HMODULE hExe = GetModuleHandleW(NULL);
        auto* dos = (IMAGE_DOS_HEADER*)hExe;
        auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            char name[9] = {}; memcpy(name, sec->Name, 8);
            if (strncmp(name, ".text", 5) != 0) continue;
            BYTE* textStart = (BYTE*)hExe + sec->VirtualAddress;
            BYTE* textEnd = textStart + sec->Misc.VirtualSize;
            if ((BYTE*)addr >= textStart && (BYTE*)addr < textEnd) {
                Log("vp blocked on .text @ 0x" + std::to_string((uintptr_t)addr));
                if (oldProt) *oldProt = PAGE_EXECUTE_READ;
                return TRUE;
            }
        }
    }
    return orig_VirtualProtect(addr, size, newProt, oldProt);
}

static BYTE* g_exeImageStart = nullptr;
static BYTE* g_exeImageEnd = nullptr;

static bool CallerIsMainExe(void* retAddr) {
    return retAddr >= g_exeImageStart && retAddr < g_exeImageEnd;
}

static decltype(&BCryptVerifySignature) orig_BCryptVerifySignature = nullptr;

static NTSTATUS WINAPI Hk_BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo,
    PUCHAR pbHash, ULONG cbHash,
    PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags) {
    NTSTATUS real = orig_BCryptVerifySignature(hKey, pPaddingInfo, pbHash, cbHash, pbSignature, cbSignature, dwFlags);
    if (real != 0) {
        Log("bcrypt verify fail 0x" + std::to_string(real) + " -> 0");
        return 0;
    }
    return 0;
}

typedef int (*EVP_DigestVerifyFinal_t)(void*, const unsigned char*, size_t);
typedef int (*EVP_DigestVerify_t)(void*, const unsigned char*, size_t, const unsigned char*, size_t);
typedef int (*EVP_PKEY_verify_t)(void*, const unsigned char*, size_t, const unsigned char*, size_t);
typedef int (*ED25519_verify_t)(const unsigned char*, size_t, const unsigned char*, const unsigned char*);

static EVP_DigestVerifyFinal_t orig_EVP_DigestVerifyFinal = nullptr;
static EVP_DigestVerify_t      orig_EVP_DigestVerify = nullptr;
static EVP_PKEY_verify_t       orig_EVP_PKEY_verify = nullptr;
static ED25519_verify_t        orig_ED25519_verify = nullptr;

static int Hk_EVP_DigestVerifyFinal(void* ctx, const unsigned char* sig, size_t sl) {
    int real = orig_EVP_DigestVerifyFinal(ctx, sig, sl);
    if (real != 1) {
        Log("evpdfv fail real=" + std::to_string(real));
    }
    else {
        Log("evpdfv ok");
    }
    return 1;
}
static int Hk_EVP_DigestVerify(void* ctx, const unsigned char* sig, size_t sl, const unsigned char* t, size_t tl) {
    int real = orig_EVP_DigestVerify(ctx, sig, sl, t, tl);
    if (real != 1)
        Log("evpdv fail real=" + std::to_string(real));
    else
        Log("evpdv ok");
    return 1;
}
static int Hk_EVP_PKEY_verify(void* ctx, const unsigned char* sig, size_t sl, const unsigned char* t, size_t tl) {
    int real = orig_EVP_PKEY_verify(ctx, sig, sl, t, tl);
    if (real != 1)
        Log("pkey verify fail real=" + std::to_string(real));
    else
        Log("pkey verify ok");
    return 1;
}
static int Hk_ED25519_verify(const unsigned char* msg, size_t ml, const unsigned char* sig, const unsigned char* pub) {
    int real = orig_ED25519_verify ? orig_ED25519_verify(msg, ml, sig, pub) : 0;
    if (real != 1)
        Log("ed25519 fail real=" + std::to_string(real));
    else
        Log("ed25519 ok");
    return 1;
}

static decltype(&recv)    orig_recv = nullptr;
static decltype(&WSARecv) orig_WSARecv = nullptr;
static volatile LONG g_pendingScan = 0;

static const char* memmem_lite(const char* h, size_t hl, const char* n, size_t nl) {
    if (nl == 0 || hl < nl) return nullptr;
    for (size_t i = 0; i + nl <= hl; i++)
        if (memcmp(h + i, n, nl) == 0) return h + i;
    return nullptr;
}

#include "universal_multistack_hooks.h"

static std::string ExtractHeader(const char* buf, ULONG len, const char* name) {
    std::string needle = std::string(name) + ": ";
    const char* p = memmem_lite(buf, len, needle.c_str(), needle.size());
    if (!p) return "";
    const char* val = p + needle.size();
    ULONG rem = len - (ULONG)(val - buf);
    const char* eol = memmem_lite(val, rem, "\r\n", 2);
    if (!eol) return "";
    return std::string(val, eol - val);
}

static volatile LONG g_recvCount = 0;
static int WSAAPI Hk_recv(SOCKET s, char* buf, int len, int flags) {
    int ret = orig_recv(s, buf, len, flags);
    if (ret > 0) {
        LONG c = InterlockedIncrement(&g_recvCount);

        if (ret >= 5 && (unsigned char)buf[0] == 0x17 && (unsigned char)buf[1] == 0x03) {
            int tls_payload = ((unsigned char)buf[3] << 8) | (unsigned char)buf[4];
            if (tls_payload + 5 == ret && len - ret >= 5) {
                u_long avail = 0;
                ioctlsocket(s, FIONREAD, &avail);
                if (avail == 0) {
                    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
                    struct timeval tv = { 0, 2000 };
                    if (select(0, &fds, nullptr, nullptr, &tv) > 0)
                        ioctlsocket(s, FIONREAD, &avail);
                }
                if (avail > 0 && (int)avail <= len - ret) {
                    int ret2 = orig_recv(s, buf + ret, len - ret, flags);
                    if (ret2 > 0) {
                        ret += ret2;
                        Log("recv: TLS coalesce +" + std::to_string(ret2)
                            + " (total=" + std::to_string(ret) + ")");
                    }
                }
            }
        }

        if (c <= 20) {
            char preview[80] = {};
            int n = (ret < 70) ? ret : 70;
            memcpy(preview, buf, n);
            for (int j = 0; j < n; j++) if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
            Log("recv #" + std::to_string(c) + " sock=" + std::to_string(s) +
                " bytes=" + std::to_string(ret) + " [" + std::string(preview) + "]");
        }
        UniversalSpoofPayload(buf, (size_t)ret, "Winsock:recv");
        InterlockedExchange(&g_pendingScan, 1);
    }
    return ret;
}

static int WSAAPI Hk_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpOverlapped, lpCompletionRoutine);
    if (ret == 0 && lpBuffers && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        LONG c = InterlockedIncrement(&g_recvCount);
        if (c <= 10)
            Log("WSARecv #" + std::to_string(c) + " sock=" + std::to_string(s) +
                " bytes=" + std::to_string(*lpNumberOfBytesRecvd));
        if (lpBuffers[0].buf) UniversalSpoofPayload(lpBuffers[0].buf, (size_t)(*lpNumberOfBytesRecvd), "Winsock:WSARecv");
        InterlockedExchange(&g_pendingScan, 1);
    }
    return ret;
}

typedef SECURITY_STATUS(SEC_ENTRY* DecryptMessage_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
static DecryptMessage_t orig_DecryptMessage = nullptr;

static volatile LONG g_decryptCount = 0;

static std::mutex g_dc2Mtx;
static char* g_dc2_buf = nullptr;
static ULONG g_dc2_bufLen = 0;
static ULONG g_dc2_jsonOff = (ULONG)-1;

static void DC_InPlaceFlip(char* buf, ULONG len) {
    for (ULONG j = 0; j + 15 < len; j++) {
        if (memcmp(buf + j, "\"success\":false", 15) == 0) {
            memcpy(buf + j, "\"success\":true ", 15);
            return;
        }
    }
}

static void DC_UpdateContentLength(char* buf, ULONG headerEnd, size_t newLen) {
    const char* tag = "Content-Length: ";
    size_t tlen = strlen(tag);
    const char* p = memmem_lite(buf, headerEnd, tag, tlen);
    if (!p) return;
    char* digits = const_cast<char*>(p + tlen);
    int dcount = 0;
    while (digits[dcount] >= '0' && digits[dcount] <= '9') dcount++;
    char newNum[24];
    int newCount = snprintf(newNum, sizeof(newNum), "%zu", newLen);
    if (newCount <= dcount) {
        memcpy(digits, newNum, newCount);
        if (newCount < dcount) memset(digits + newCount, ' ', dcount - newCount);
        Log("UpdateContentLength -> " + std::to_string(newLen));
    }
}

// main TLS bypass — intercepts after SChannel decrypts, rewrites failed auth responses before the app reads them
static SECURITY_STATUS SEC_ENTRY Hk_DecryptMessage(PCtxtHandle phCtx, PSecBufferDesc pMsg,
    ULONG seq, PULONG qop) {
    LONG c = InterlockedIncrement(&g_decryptCount);
    SECURITY_STATUS st = orig_DecryptMessage(phCtx, pMsg, seq, qop);
    if (st != SEC_E_OK || !pMsg) return st;

    for (ULONG i = 0; i < pMsg->cBuffers; i++) {
        SecBuffer& sb = pMsg->pBuffers[i];
        if (sb.BufferType != SECBUFFER_DATA || !sb.pvBuffer || sb.cbBuffer < 10) continue;

        char* buf = (char*)sb.pvBuffer;
        ULONG len = sb.cbBuffer;

        {
            char preview[120] = {};
            int pn = (int)(len < 100 ? len : 100);
            memcpy(preview, buf, pn);
            for (int j = 0; j < pn; j++)
                if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
            Log("DecryptMessage #" + std::to_string(c) + " len=" + std::to_string(len) +
                " [" + std::string(preview) + "]");
        }

        DumpResponse((int)c, buf, len);

        std::lock_guard<std::mutex> lk(g_dc2Mtx);

        if (memmem_lite(buf, len, "\"success\":false", 15)) {
            std::string sig = ExtractHeader(buf, len, "x-signature-ed25519");
            std::string ts = ExtractHeader(buf, len, "x-signature-timestamp");
            Log("decrypt: sig=" + (sig.empty() ? "missing" : sig.substr(0, 16) + "...") +
                " ts=" + (ts.empty() ? "missing" : ts));

            ULONG jOff = (ULONG)-1;
            for (ULONG k = 0; k < len; k++) {
                if (buf[k] == '{') { jOff = k; break; }
            }

            std::string nonce, ownerid;

            SecBuffer* extraBuf = nullptr;
            for (ULONG ei = 0; ei < pMsg->cBuffers; ei++) {
                if (pMsg->pBuffers[ei].BufferType == SECBUFFER_EXTRA &&
                    pMsg->pBuffers[ei].pvBuffer && pMsg->pBuffers[ei].cbBuffer > 0) {
                    extraBuf = &pMsg->pBuffers[ei];
                    break;
                }
            }

            if (extraBuf) {
                SecBuffer inbuf2[4] = {
                    { extraBuf->cbBuffer, SECBUFFER_DATA, extraBuf->pvBuffer },
                    { 0, SECBUFFER_EMPTY, nullptr },
                    { 0, SECBUFFER_EMPTY, nullptr },
                    { 0, SECBUFFER_EMPTY, nullptr }
                };
                SecBufferDesc desc2 = { SECBUFFER_VERSION, 4, inbuf2 };
                ULONG qop2 = 0;
                SECURITY_STATUS st2 = orig_DecryptMessage(phCtx, &desc2, 0, &qop2);
                if (st2 == SEC_E_OK) {
                    for (int ii = 0; ii < 4; ii++) {
                        if (inbuf2[ii].BufferType == SECBUFFER_DATA &&
                            inbuf2[ii].pvBuffer && inbuf2[ii].cbBuffer > 0) {
                            char* buf2 = (char*)inbuf2[ii].pvBuffer;
                            ULONG len2 = inbuf2[ii].cbBuffer;
                            Log("decrypt: buf2 ok len=" + std::to_string(len2));
                            if (jOff != (ULONG)-1) {
                                std::string accum(buf + jOff, len - jOff);
                                accum.append(buf2, len2);
                                nonce = ExtractNonce(accum.data(), accum.size());
                                ownerid = ExtractOwnerid(accum.data(), accum.size());
                            }
                            break;
                        }
                    }
                }
                else {
                    Log("decrypt: buf2 fail 0x" + std::to_string((uint32_t)st2));
                }
            }

            if (nonce.empty() && jOff != (ULONG)-1) {
                nonce = ExtractNonce(buf + jOff, len - jOff);
                ownerid = ExtractOwnerid(buf + jOff, len - jOff);
            }

            if (!nonce.empty()) {
                std::string fakeBody = BuildSuccessJSON(nonce, ownerid);
                std::string newSig = sig;
                if (!ts.empty()) {
                    std::string msgToSign = ts + fakeBody;
                    uint8_t sigBytes[64] = {};
                    ed25519_sign_detached(sigBytes,
                        (const uint8_t*)msgToSign.data(), msgToSign.size(), FAKE_SK);
                    newSig = BytesToHex(sigBytes, 64);
                    Log("decrypt: re-signed sig=" + newSig.substr(0, 16) + "...");
                }
                std::string fakeHttp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: " + std::to_string(fakeBody.size()) + "\r\n"
                    "x-signature-ed25519: " + newSig + "\r\n"
                    "x-signature-timestamp: " + ts + "\r\n"
                    "\r\n" + fakeBody;

                if (fakeHttp.size() <= len) {
                    memcpy(buf, fakeHttp.c_str(), fakeHttp.size());
                    memset(buf + fakeHttp.size(), 0, len - fakeHttp.size());
                    sb.cbBuffer = (ULONG)fakeHttp.size();
                    if (extraBuf) {
                        extraBuf->BufferType = SECBUFFER_EMPTY;
                        extraBuf->cbBuffer = 0;
                        extraBuf->pvBuffer = nullptr;
                    }
                    Log("decrypt: rewrite ok nonce=" + nonce +
                        " size=" + std::to_string(fakeHttp.size()));
                }
                else {
                    DC_InPlaceFlip(buf, len);
                    Log("decrypt: flip fallback (too large)");
                }
                g_dc2_buf = nullptr; g_dc2_bufLen = 0; g_dc2_jsonOff = (ULONG)-1;
            }
            else {
                DC_InPlaceFlip(buf, len);
                Log("decrypt: no nonce, flip fallback");
                g_dc2_buf = buf;
                g_dc2_bufLen = len;
                g_dc2_jsonOff = jOff;
            }
            InterlockedExchange(&g_pendingScan, 1);
            continue;
        }

        if (g_dc2_buf && g_dc2_jsonOff != (ULONG)-1) {
            Log("DecryptMessage: Case B fallback (dropped from v3 bypass path)");
            g_dc2_buf = nullptr; g_dc2_bufLen = 0; g_dc2_jsonOff = (ULONG)-1;
            InterlockedExchange(&g_pendingScan, 1);
        }
        UniversalSpoofPayload(buf, (size_t)len, "SChannel:DecryptMessage");
    }
    return st;
}


typedef void(__cdecl* exit_t)(int);
typedef void(__cdecl* abort_t)();
typedef void(__cdecl* terminate_t)();
typedef int(__cdecl* system_t)(const char*);
static exit_t      orig_exit = nullptr;
static exit_t      orig__exit = nullptr;
static abort_t     orig_abort = nullptr;
static terminate_t orig_terminate = nullptr;
static terminate_t orig_std_terminate = nullptr;
static system_t    orig_system = nullptr;

static int __cdecl Hk_system(const char* cmd) {
    Log("[system] cmd='" + std::string(cmd ? cmd : "(null)") + "'");
    if (cmd) {
        std::string s(cmd);
        if (s.find("signature verify failed") != std::string::npos ||
            _stricmp(cmd, "pause") == 0) {
            Log("system(): suppressed (request guard bypass)");
            return 0;
        }
    }
    return orig_system ? orig_system(cmd) : 0;
}

static void __cdecl Hk_exit(int code) {
    Log("!!! exit(" + std::to_string(code) + ") from 0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (code == 7 || code == 1) {
        Log("exit(" + std::to_string(code) + ") SUPPRESSED — sig bypass: returning to caller");
        return;
    }
    if (orig_exit) orig_exit(code); else ExitProcess(code);
}
static void __cdecl Hk__exit(int code) {
    Log("!!! _exit(" + std::to_string(code) + ") from 0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (code == 7 || code == 1) {
        Log("_exit(" + std::to_string(code) + ") SUPPRESSED — sig bypass: returning to caller");
        return;
    }
    if (orig__exit) orig__exit(code); else ExitProcess(code);
}
static void __cdecl Hk_abort() {
    Log("!!! abort() from 0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (orig_abort) orig_abort(); else ExitProcess(3);
}
static void __cdecl Hk_terminate() {
    Log("!!! terminate() from 0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (orig_terminate) orig_terminate(); else ExitProcess(3);
}
static void __cdecl Hk_std_terminate() {
    Log("!!! __std_terminate() from 0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (orig_std_terminate) orig_std_terminate(); else ExitProcess(3);
}

typedef int(WINAPI* MsgBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef int(WINAPI* MsgBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
static MsgBoxA_t orig_MessageBoxA = nullptr;
static MsgBoxW_t orig_MessageBoxW = nullptr;

static int WINAPI Hk_MessageBoxA(HWND h, LPCSTR txt, LPCSTR cap, UINT type) {
    Log("!!! MessageBoxA caption='" + std::string(cap ? cap : "") +
        "' text='" + std::string(txt ? txt : "") + "'");
    if (txt && strstr(txt, "Signature verification failed"))
        return IDOK;
    return orig_MessageBoxA ? orig_MessageBoxA(h, txt, cap, type) : 1;
}
static int WINAPI Hk_MessageBoxW(HWND h, LPCWSTR txt, LPCWSTR cap, UINT type) {
    char ct[512] = {}, cc[256] = {};
    if (txt) WideCharToMultiByte(CP_UTF8, 0, txt, -1, ct, sizeof(ct) - 1, nullptr, nullptr);
    if (cap) WideCharToMultiByte(CP_UTF8, 0, cap, -1, cc, sizeof(cc) - 1, nullptr, nullptr);
    Log("!!! MessageBoxW caption='" + std::string(cc) + "' text='" + std::string(ct) + "'");
    return orig_MessageBoxW ? orig_MessageBoxW(h, txt, cap, type) : 1;
}

typedef int(__cdecl* puts_t)(const char*);
typedef int(__cdecl* _write_t)(int, const void*, unsigned int);
static puts_t   orig_puts = nullptr;
static _write_t orig__write = nullptr;

static int __cdecl Hk_puts(const char* s) {
    if (s) {
        std::string m(s);
        if (m.size() > 200) m = m.substr(0, 200) + "...";
        Log("[puts] " + m);
        if (m.find("signature verify failed") != std::string::npos ||
            m.find("Waiting for") != std::string::npos) {
            Log("puts: suppressed request guard error");
            return 0;
        }
    }
    return orig_puts ? orig_puts(s) : 0;
}
static int __cdecl Hk__write(int fd, const void* buf, unsigned int n) {
    if (n > 0 && buf && (fd == 1 || fd == 2)) {
        std::string m((const char*)buf, n > 200 ? 200 : n);
        for (auto& c : m) if (c == '\n' || c == '\r') c = '|';
        Log("[fd" + std::to_string(fd) + " _write " + std::to_string(n) + "] " + m);
        if (fd == 2 && m.find("Signature verification failed") != std::string::npos) {
            Log("_write(2): suppressed sig error output");
            return (int)n;
        }
    }
    return orig__write ? orig__write(fd, buf, n) : (int)n;
}

typedef int(WSAAPI* connect_t)(SOCKET, const sockaddr*, int);
typedef int(WSAAPI* send_t)(SOCKET, const char*, int, int);
static connect_t orig_connect = nullptr;
static send_t    orig_send = nullptr;

static int WSAAPI Hk_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (name) {
        char ip[INET6_ADDRSTRLEN] = "(non-IPv4)";
        int port = 0;
        if (name->sa_family == AF_INET) {
            auto* in = (const sockaddr_in*)name;
            inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
            port = ntohs(in->sin_port);
        }
        else if (name->sa_family == AF_INET6) {
            auto* in6 = (const sockaddr_in6*)name;
            inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
            port = ntohs(in6->sin6_port);
        }
        Log("connect() sock=" + std::to_string(s) + " -> " + std::string(ip) + ":" + std::to_string(port));
    }
    return orig_connect ? orig_connect(s, name, namelen) : -1;
}

static volatile LONG g_sendCount = 0;
static int WSAAPI Hk_send(SOCKET s, const char* buf, int len, int flags) {
    LONG c = InterlockedIncrement(&g_sendCount);
    if (c <= 20 && buf && len > 0) {
        char preview[120] = {};
        int n = len < 100 ? len : 100;
        memcpy(preview, buf, n);
        for (int j = 0; j < n; j++) if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
        Log("send #" + std::to_string(c) + " sock=" + std::to_string(s) +
            " len=" + std::to_string(len) + " [" + std::string(preview) + "]");
    }
    return orig_send ? orig_send(s, buf, len, flags) : -1;
}

typedef int(WSAAPI* WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSASend_t orig_WSASend = nullptr;

static int WSAAPI Hk_WSASend(SOCKET s, LPWSABUF lpBufs, DWORD cnt, LPDWORD pSent,
    DWORD flags, LPWSAOVERLAPPED lpOv,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCR) {
    if (lpBufs && cnt > 0 && lpBufs[0].buf && lpBufs[0].len > 0) {
        static volatile LONG wsaSendCount = 0;
        LONG c = InterlockedIncrement(&wsaSendCount);
        if (c <= 10) {
            char preview[120] = {};
            ULONG n = lpBufs[0].len < 100 ? lpBufs[0].len : 100;
            memcpy(preview, lpBufs[0].buf, n);
            for (ULONG j = 0; j < n; j++) if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
            Log("WSASend #" + std::to_string(c) + " sock=" + std::to_string(s) +
                " len=" + std::to_string(lpBufs[0].len) + " [" + std::string(preview) + "]");
        }
    }
    return orig_WSASend ? orig_WSASend(s, lpBufs, cnt, pSent, flags, lpOv, lpCR) : -1;
}

typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPDWORD);
static CreateThread_t orig_CreateThread = nullptr;

static HANDLE WINAPI Hk_CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stackSize,
    LPTHREAD_START_ROUTINE fn, LPVOID arg,
    DWORD creationFlags, LPDWORD pTid) {
    HANDLE ret = orig_CreateThread(sa, stackSize, fn, arg, creationFlags, pTid);
    DWORD tid = pTid ? *pTid : 0;
    Log("CreateThread: fn=0x" + std::to_string((uintptr_t)fn) +
        " arg=0x" + std::to_string((uintptr_t)arg) +
        " flags=0x" + std::to_string(creationFlags) +
        " tid=" + std::to_string(tid) +
        " caller=0x" + std::to_string((uintptr_t)_ReturnAddress()));
    if (ret && (g_hwbpTarget || g_hwbpTarget2)) {
        BOOL wasSusp = (creationFlags & CREATE_SUSPENDED) != 0;
        if (!wasSusp) SuspendThread(ret);
        SetHWBPOnThread(ret);
        if (!wasSusp) ResumeThread(ret);
    }
    return ret;
}

typedef DWORD(WINAPI* WaitForSO_t)(HANDLE, DWORD);
static WaitForSO_t orig_WaitForSingleObject = nullptr;
static volatile LONG g_waitCount = 0;

static DWORD WINAPI Hk_WaitForSingleObject(HANDLE h, DWORD ms) {
    LONG c = InterlockedIncrement(&g_waitCount);
    bool isLong = (ms == INFINITE || ms > 5000);
    if (c <= 30 || isLong) {
        Log("WaitForSingleObject #" + std::to_string(c) +
            " handle=0x" + std::to_string((uintptr_t)h) +
            " ms=" + (ms == INFINITE ? "INFINITE" : std::to_string(ms)) +
            " caller=0x" + std::to_string((uintptr_t)_ReturnAddress()));
    }
    DWORD ret = orig_WaitForSingleObject(h, ms);
    if (isLong || c <= 30) {
        Log("WaitForSingleObject #" + std::to_string(c) + " returned 0x" + std::to_string(ret));
    }
    return ret;
}

typedef void(WINAPI* Sleep_t)(DWORD);
static Sleep_t orig_Sleep = nullptr;

static void WINAPI Hk_Sleep(DWORD ms) {
    if (ms > 500) {
        Log("Sleep(" + std::to_string(ms) + ") from 0x" +
            std::to_string((uintptr_t)_ReturnAddress()));
    }
    if (orig_Sleep) orig_Sleep(ms);
}

typedef FARPROC(WINAPI* GetProcAddr_t)(HMODULE, LPCSTR);
static GetProcAddr_t orig_GetProcAddress = nullptr;
static volatile LONG g_gpaCount = 0;

static FARPROC WINAPI Hk_GetProcAddress(HMODULE hMod, LPCSTR name) {
    FARPROC ret = orig_GetProcAddress(hMod, name);
    if (name && !IMAGE_SNAP_BY_ORDINAL((uintptr_t)name)) {
        LONG c = InterlockedIncrement(&g_gpaCount);
        if (c <= 100) {
            char modName[64] = "(unknown)";
            GetModuleFileNameA(hMod, modName, sizeof(modName));
            char* sl = strrchr(modName, '\\');
            Log("GetProcAddress: " + std::string(sl ? sl + 1 : modName) + "!" + std::string(name));
        }
    }
    return ret;
}

typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE, CONTEXT*);
typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE, CONTEXT*);
static NtGetContextThread_t orig_NtGetContextThread = nullptr;
static NtSetContextThread_t orig_NtSetContextThread = nullptr;

// zeroes DR0-DR7 in the output so the app can't detect our hardware breakpoints
static NTSTATUS NTAPI Hk_NtGetContextThread(HANDLE hThread, CONTEXT* ctx) {
    NTSTATUS st = orig_NtGetContextThread(hThread, ctx);
    if (st == 0 && ctx && (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        ctx->Dr0 = ctx->Dr1 = ctx->Dr2 = ctx->Dr3 = ctx->Dr6 = ctx->Dr7 = 0;
    }
    return st;
}

// blocks the app from clearing DR regs (Dr7=0 means "clear all breakpoints")
static NTSTATUS NTAPI Hk_NtSetContextThread(HANDLE hThread, CONTEXT* ctx) {
    if (ctx && (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS)
        && ctx->Dr7 == 0
        && (g_hwbpTarget || g_hwbpTarget2)) {
        ctx->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    }
    return orig_NtSetContextThread(hThread, ctx);
}

typedef LONG(WINAPI* RegQVExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegQVExW_t orig_RegQueryValueExW = nullptr;

static LONG WINAPI Hk_RegQueryValueExW(HKEY hKey, LPCWSTR lpName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    LONG ret = orig_RegQueryValueExW(hKey, lpName, lpReserved, lpType, lpData, lpcbData);
    if (lpName) {
        char n[256] = {};
        WideCharToMultiByte(CP_ACP, 0, lpName, -1, n, sizeof(n) - 1, nullptr, nullptr);
        static volatile LONG regCount = 0;
        LONG c = InterlockedIncrement(&regCount);
        if (c <= 50)
            Log("RegQueryValueExW: \"" + std::string(n) + "\" ret=" + std::to_string(ret));
    }
    return ret;
}


typedef int (*SSL_read_t)(void*, void*, int);
typedef int (*SSL_read_ex_t)(void*, void*, size_t, size_t*);
static SSL_read_t    orig_SSL_read = nullptr;
static SSL_read_ex_t orig_SSL_read_ex = nullptr;

static int RewriteHTTPResponse(char* buf, int dataLen, int bufCap) {
    if (dataLen <= 0 || !buf) return dataLen;
    const char* end = buf + dataLen;

    if (!memmem_lite(buf, dataLen, "\"success\":false", 15)) return dataLen;
    if (!memmem_lite(buf, dataLen, "\"nonce\"", 7))  return dataLen;

    const char* js = (const char*)memchr(buf, '{', dataLen);
    if (!js) return dataLen;
    std::string nonce = ExtractNonce(js, (size_t)(end - js));
    if (nonce.empty()) return dataLen;
    std::string ownerid = ExtractOwnerid(js, (size_t)(end - js));
    std::string newBody = BuildSuccessJSON(nonce, ownerid);

    bool hasHttp = !!memmem_lite(buf, dataLen, "HTTP/", 5);
    if (hasHttp) {
        std::string newResp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(newBody.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + newBody;
        if ((int)newResp.size() <= bufCap) {
            memcpy(buf, newResp.c_str(), newResp.size());
            Log("SSL_read rewrite (full HTTP): " + std::to_string(dataLen) +
                " -> " + std::to_string(newResp.size()) + " (nonce=" + nonce + ")");
            return (int)newResp.size();
        }
        Log("SSL_read rewrite: buffer too small (" + std::to_string(newResp.size()) +
            " > " + std::to_string(bufCap) + "), falling back to in-place");
    }
    else {
        if ((int)newBody.size() <= bufCap) {
            memcpy(buf, newBody.c_str(), newBody.size());
            if (newBody.size() < (size_t)dataLen)
                memset(buf + newBody.size(), ' ', dataLen - newBody.size());
            Log("SSL_read rewrite (body-only): " + std::to_string(dataLen) +
                " -> " + std::to_string(newBody.size()) + " (nonce=" + nonce + ")");
            return (int)newBody.size();
        }
    }

    for (int i = 0; i + 15 < dataLen; i++) {
        if (memcmp(buf + i, "\"success\":false", 15) == 0) {
            memcpy(buf + i, "\"success\":true ", 15);
            Log("SSL_read: in-place flip applied (fallback)");
            break;
        }
    }
    return dataLen;
}

static volatile LONG g_sslReadCount = 0;
static int Hk_SSL_read(void* ssl, void* buf, int num) {
    int ret = orig_SSL_read(ssl, buf, num);
    LONG c = InterlockedIncrement(&g_sslReadCount);
    if (ret > 0) {
        if (c <= 20) {
            char preview[80] = {};
            int n = ret < 70 ? ret : 70;
            memcpy(preview, buf, n);
            for (int j = 0; j < n; j++)
                if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
            Log("SSL_read #" + std::to_string(c) + " ret=" + std::to_string(ret) +
                " [" + std::string(preview) + "]");
        }
        int newSize = RewriteHTTPResponse((char*)buf, ret, num);
        if (newSize != ret) {
            InterlockedExchange(&g_pendingScan, 1);
            return newSize;
        }
    }
    return ret;
}

static int Hk_SSL_read_ex(void* ssl, void* buf, size_t num, size_t* readbytes) {
    int ret = orig_SSL_read_ex(ssl, buf, num, readbytes);
    LONG c = InterlockedIncrement(&g_sslReadCount);
    if (ret == 1 && readbytes && *readbytes > 0) {
        if (c <= 20) {
            char preview[80] = {};
            int n = (int)(*readbytes < 70 ? *readbytes : 70);
            memcpy(preview, buf, n);
            for (int j = 0; j < n; j++)
                if ((unsigned char)preview[j] < 32 || preview[j] > 126) preview[j] = '.';
            Log("SSL_read_ex #" + std::to_string(c) + " bytes=" + std::to_string(*readbytes) +
                " [" + std::string(preview) + "]");
        }
        int newSize = RewriteHTTPResponse((char*)buf, (int)*readbytes, (int)num);
        if (newSize > 0 && (size_t)newSize != *readbytes) {
            *readbytes = (size_t)newSize;
            InterlockedExchange(&g_pendingScan, 1);
        }
    }
    return ret;
}

// polls g_pendingScan flag that recv/WSARecv/SSL_read hooks set when they see new data
static DWORD WINAPI ScanThread(LPVOID) {
    int hb = 0;
    while (true) {
        Sleep(20);
        hb++;
        if (hb % 3000 == 0) Log("ScanThread alive #" + std::to_string(hb / 3000));
        if (InterlockedExchange(&g_pendingScan, 0)) {
            Log("heap scan");
            for (int attempt = 0; attempt < 3; attempt++) {
                ScanAndPatchHeap();
                Sleep(50);
            }
        }
    }
    return 0;
}

#pragma pack(push, 1)
struct NTPPacket {
    uint8_t  li_vn_mode;
    uint8_t  stratum, poll; int8_t precision;
    uint32_t rootDelay, rootDispersion, refId;
    uint32_t refTm_s, refTm_f, origTm_s, origTm_f;
    uint32_t rxTm_s, rxTm_f, txTm_s, txTm_f;
};
#pragma pack(pop)

static bool QueryNTPTime(SYSTEMTIME* out) {
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    static const char* kServers[] = {
        "pool.ntp.org", "time.cloudflare.com", "time.windows.com"
    };
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;
    DWORD tv = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    bool ok = false;
    for (auto srv : kServers) {
        addrinfo hints = {}, * ai = nullptr;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(srv, "123", &hints, &ai) != 0) continue;

        NTPPacket pkt = {}; pkt.li_vn_mode = 0x1B;
        int sent = sendto(s, (char*)&pkt, sizeof(pkt), 0, ai->ai_addr, (int)ai->ai_addrlen);
        freeaddrinfo(ai);
        if (sent == SOCKET_ERROR) continue;

        NTPPacket resp = {};
        struct sockaddr_in from = {}; int fl = sizeof(from);
        if (recvfrom(s, (char*)&resp, sizeof(resp), 0, (sockaddr*)&from, &fl) < (int)sizeof(resp)) continue;

        uint32_t ntpSec = ntohl(resp.txTm_s);
        if (ntpSec < 2208988800UL) continue;

        uint64_t unixSec = ntpSec - 2208988800UL;
        ULARGE_INTEGER ft; ft.QuadPart = (unixSec + 11644473600ULL) * 10000000ULL;
        FILETIME ftm; ftm.dwLowDateTime = ft.LowPart; ftm.dwHighDateTime = ft.HighPart;
        FileTimeToSystemTime(&ftm, out);
        ok = true; break;
    }
    closesocket(s);
    return ok;
}

static void CheckExpiry() {
#if EXPIRY_YEAR == 0
    return;
#else
    static const uint32_t XK = 0xC0DEBABE;
    static const uint32_t ED = (uint32_t)((EXPIRY_YEAR * 10000UL +
        EXPIRY_MONTH * 100UL +
        EXPIRY_DAY) ^ XK);
    uint32_t expYMD = ED ^ XK;
    int expYear = (int)(expYMD / 10000);
    int expMonth = (int)(expYMD / 100 % 100);
    int expDay = (int)(expYMD % 100);

    Sleep(1000);
    SYSTEMTIME now = {};
    if (!QueryNTPTime(&now)) {
        Log("Expiry: NTP failed — exiting");
        ExitProcess(0);
    }

    int nowYMD = now.wYear * 10000 + now.wMonth * 100 + now.wDay;
    if (nowYMD >= expYear * 10000 + expMonth * 100 + expDay) {
        Log("Expiry: EXPIRED — exiting");
        ExitProcess(0);
    }
    Log("Expiry: OK — NTP: " + std::to_string(now.wDay) + "." +
        std::to_string(now.wMonth) + "." + std::to_string(now.wYear));
#endif
}

static DWORD WINAPI ShowMsgBoxThread(LPVOID) {
    MessageBoxW(NULL,
        L"Keyauth 1.3 Patcher\n\n"
        L"This is a free program. If you paid for this you got scammed\n\n"
        L"Discord: Kariexscontxct",
        L"Keyauth 1.3 Patcher", MB_ICONINFORMATION);
    return 0;
}
static void ShowStartupMessage() {
    HANDLE h = CreateThread(NULL, 0, ShowMsgBoxThread, NULL, 0, NULL);
    if (h) CloseHandle(h);
}

static DWORD WINAPI MainThread(LPVOID) {
    // OmniReverse Clean Build: Startup nag & NTP timebomb disabled

    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    Log("=== KeyAuth Patcher v9 started, exe=" + std::string(exePath) + " ===");
    Log("Log file: " + std::string(g_logPath));

    {
        HMODULE hExe = GetModuleHandleW(NULL);
        auto* dos = (IMAGE_DOS_HEADER*)hExe;
        auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);
        g_exeImageStart = (BYTE*)hExe;
        g_exeImageEnd = g_exeImageStart + nt->OptionalHeader.SizeOfImage;
        Log("EXE image: 0x" + std::to_string((uintptr_t)g_exeImageStart) +
            " - 0x" + std::to_string((uintptr_t)g_exeImageEnd));
    }

    int sigPatched = 0;
    MH_Initialize();

    orig_CreateFileW = (decltype(&CreateFileW))
        IATHook("KERNEL32.DLL", "CreateFileW", (void*)Hk_CreateFileW);
    orig_CreateFileMappingW = (decltype(&CreateFileMappingW))
        IATHook("KERNEL32.DLL", "CreateFileMappingW", (void*)Hk_CreateFileMappingW);
    orig_MapViewOfFile = (decltype(&MapViewOfFile))
        IATHook("KERNEL32.DLL", "MapViewOfFile", (void*)Hk_MapViewOfFile);
    orig_UnmapViewOfFile = (decltype(&UnmapViewOfFile))
        IATHook("KERNEL32.DLL", "UnmapViewOfFile", (void*)Hk_UnmapViewOfFile);
    orig_QueryFullProcessImageNameW = (decltype(&QueryFullProcessImageNameW))
        IATHook("KERNEL32.DLL", "QueryFullProcessImageNameW", (void*)Hk_QueryFullProcessImageNameW);
    orig_VirtualProtect = (decltype(&VirtualProtect))
        IATHook("KERNEL32.DLL", "VirtualProtect", (void*)Hk_VirtualProtect);

    HMODULE hWs2 = LoadLibraryW(L"ws2_32.dll");
    if (hWs2) {
        if (auto p = GetProcAddress(hWs2, "recv"))    MH_CreateHook(p, Hk_recv, (void**)&orig_recv);
        if (auto p = GetProcAddress(hWs2, "WSARecv")) MH_CreateHook(p, Hk_WSARecv, (void**)&orig_WSARecv);
        if (auto p = GetProcAddress(hWs2, "WSASend")) MH_CreateHook(p, Hk_WSASend, (void**)&orig_WSASend);
        if (auto p = GetProcAddress(hWs2, "connect")) MH_CreateHook(p, Hk_connect, (void**)&orig_connect);
        if (auto p = GetProcAddress(hWs2, "send"))    MH_CreateHook(p, Hk_send, (void**)&orig_send);
    }

    HMODULE hBcrypt = LoadLibraryW(L"bcrypt.dll");
    if (hBcrypt)
        if (auto p = GetProcAddress(hBcrypt, "BCryptVerifySignature"))
            MH_CreateHook(p, Hk_BCryptVerifySignature, (void**)&orig_BCryptVerifySignature);

    const wchar_t* opensslDlls[] = {
        L"libcrypto-3-x64.dll", L"libcrypto-3.dll",
        L"libcrypto-1_1-x64.dll", L"libcrypto-1_1.dll", nullptr
    };
    for (int i = 0; opensslDlls[i]; i++) {
        HMODULE h = GetModuleHandleW(opensslDlls[i]);
        if (!h) h = LoadLibraryW(opensslDlls[i]);
        if (!h) continue;
        Log("OpenSSL DLL: 0x" + std::to_string((uintptr_t)h));
        if (auto p = GetProcAddress(h, "EVP_DigestVerifyFinal"))
            MH_CreateHook(p, Hk_EVP_DigestVerifyFinal, (void**)&orig_EVP_DigestVerifyFinal);
        if (auto p = GetProcAddress(h, "EVP_DigestVerify"))
            MH_CreateHook(p, Hk_EVP_DigestVerify, (void**)&orig_EVP_DigestVerify);
        if (auto p = GetProcAddress(h, "EVP_PKEY_verify"))
            MH_CreateHook(p, Hk_EVP_PKEY_verify, (void**)&orig_EVP_PKEY_verify);
        if (auto p = GetProcAddress(h, "ED25519_verify"))
            MH_CreateHook(p, Hk_ED25519_verify, (void**)&orig_ED25519_verify);
        break;
    }

    const wchar_t* sslDlls[] = { L"libssl-3-x64.dll", L"libssl-3.dll",
                                  L"libssl-1_1-x64.dll", L"libssl-1_1.dll", nullptr };
    for (int i = 0; sslDlls[i]; i++) {
        HMODULE h = GetModuleHandleW(sslDlls[i]);
        if (!h) h = LoadLibraryW(sslDlls[i]);
        if (!h) continue;
        Log("libssl loaded: " + std::to_string((uintptr_t)h));
        if (auto p = GetProcAddress(h, "SSL_read"))
            MH_CreateHook(p, Hk_SSL_read, (void**)&orig_SSL_read);
        if (auto p = GetProcAddress(h, "SSL_read_ex"))
            MH_CreateHook(p, Hk_SSL_read_ex, (void**)&orig_SSL_read_ex);
        break;
    }

    for (auto name : { L"secur32.dll", L"sspicli.dll" }) {
        HMODULE h = GetModuleHandleW(name);
        if (!h) h = LoadLibraryW(name);
        if (!h) continue;
        if (auto p = GetProcAddress(h, "DecryptMessage"))
            if (!orig_DecryptMessage)
                MH_CreateHook(p, Hk_DecryptMessage, (void**)&orig_DecryptMessage);
    }

    if (auto hUser = LoadLibraryW(L"user32.dll")) {
        if (auto p = GetProcAddress(hUser, "MessageBoxA")) MH_CreateHook(p, Hk_MessageBoxA, (void**)&orig_MessageBoxA);
        if (auto p = GetProcAddress(hUser, "MessageBoxW")) MH_CreateHook(p, Hk_MessageBoxW, (void**)&orig_MessageBoxW);
    }
    for (auto name : { L"ucrtbase.dll", L"vcruntime140.dll", L"msvcrt.dll" }) {
        HMODULE h = GetModuleHandleW(name);
        if (!h) continue;
        Log("CRT: " + std::to_string((uintptr_t)h));
        if (auto p = GetProcAddress(h, "exit"))   MH_CreateHook(p, Hk_exit, (void**)&orig_exit);
        if (auto p = GetProcAddress(h, "_exit"))  MH_CreateHook(p, Hk__exit, (void**)&orig__exit);
        if (auto p = GetProcAddress(h, "abort"))  MH_CreateHook(p, Hk_abort, (void**)&orig_abort);
        if (auto p = GetProcAddress(h, "terminate")) MH_CreateHook(p, Hk_terminate, (void**)&orig_terminate);
        if (auto p = GetProcAddress(h, "puts"))   MH_CreateHook(p, Hk_puts, (void**)&orig_puts);
        if (auto p = GetProcAddress(h, "_write")) MH_CreateHook(p, Hk__write, (void**)&orig__write);
        if (auto p = GetProcAddress(h, "system")) MH_CreateHook(p, Hk_system, (void**)&orig_system);
        break;
    }
    if (auto hVcrt = GetModuleHandleW(L"VCRUNTIME140.dll"))
        if (auto p = GetProcAddress(hVcrt, "__std_terminate"))
            MH_CreateHook(p, Hk_std_terminate, (void**)&orig_std_terminate);

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        if (auto p = GetProcAddress(hK32, "CreateThread"))
            MH_CreateHook(p, Hk_CreateThread, (void**)&orig_CreateThread);
        if (auto p = GetProcAddress(hK32, "WaitForSingleObject"))
            MH_CreateHook(p, Hk_WaitForSingleObject, (void**)&orig_WaitForSingleObject);
        if (auto p = GetProcAddress(hK32, "Sleep"))
            MH_CreateHook(p, Hk_Sleep, (void**)&orig_Sleep);
        if (auto p = GetProcAddress(hK32, "GetProcAddress"))
            MH_CreateHook(p, Hk_GetProcAddress, (void**)&orig_GetProcAddress);
    }
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    if (!hAdv) hAdv = LoadLibraryW(L"advapi32.dll");
    if (hAdv)
        if (auto p = GetProcAddress(hAdv, "RegQueryValueExW"))
            MH_CreateHook(p, Hk_RegQueryValueExW, (void**)&orig_RegQueryValueExW);

    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            if (auto p = GetProcAddress(hNtdll, "NtGetContextThread"))
                MH_CreateHook(p, Hk_NtGetContextThread, (void**)&orig_NtGetContextThread);
            if (auto p = GetProcAddress(hNtdll, "NtSetContextThread"))
                MH_CreateHook(p, Hk_NtSetContextThread, (void**)&orig_NtSetContextThread);
            Log("nt ctx hooks ok");
        }
    }

    HookVerifyDetached();

    HookSigVerifyFunc();

    HookPubkeyGetter();

    InstallUniversalMultiStackHooks();

    MH_EnableHook(MH_ALL_HOOKS);

    bool useHWBP = false;
    {
        HANDLE hProt = OpenMutexW(SYNCHRONIZE, FALSE, L"KeyAuthPatcher_Protected");
        HANDLE hNon = OpenMutexW(SYNCHRONIZE, FALSE, L"KeyAuthPatcher_NonProtected");
        if (hProt) { useHWBP = true;  CloseHandle(hProt); Log("mode: protected (HWBP)"); }
        else if (hNon) { useHWBP = false; CloseHandle(hNon);  Log("mode: non-protected (MinHook)"); }
        else { useHWBP = IsVmpProtected(); Log("mode: auto-detect " + std::string(useHWBP ? "VMP" : "non-VMP")); }
    }

    bool vehAdded = false;
    if (useHWBP) {
        if (g_sodiumVerifyAddr) {
            MH_DisableHook(g_sodiumVerifyAddr);
            g_hwbpTarget = (DWORD64)g_sodiumVerifyAddr;
            char buf[80];
            snprintf(buf, sizeof(buf), "dr0 = RVA 0x%llx",
                (unsigned long long)((DWORD64)g_sodiumVerifyAddr - (DWORD64)GetModuleHandleW(NULL)));
            Log(buf);
            vehAdded = true;
        }
        if (g_hwbpTarget2) {
            char buf[80];
            snprintf(buf, sizeof(buf), "dr1 = RVA 0x%llx",
                (unsigned long long)(g_hwbpTarget2 - (DWORD64)GetModuleHandleW(NULL)));
            Log(buf);
            vehAdded = true;
        }
    }
    else {
        g_hwbpTarget = 0;
        g_hwbpTarget2 = 0;
        Log("hwbp: skipped (non-protected)");
    }
    if (vehAdded) {
        g_vehHandle = AddVectoredExceptionHandler(1, VEH_SodiumHook);
        SetHWBPOnThread(GetCurrentThread());
        SetHWBPOnAllThreads();
    }

    sigPatched = PatchSignatureVerify();
    Log("sig bypass: " + std::to_string(sigPatched) + " jumps");
    int univPatched = PatchUniversalNonKeyAuthBranches();
    Log("universal non-KeyAuth branch bypass: " + std::to_string(univPatched) + " jumps");

    Log("=== Hook Summary ===");
    Log("PE sig bypass:       " + std::to_string(sigPatched) + " jumps");
    Log("SSL_read MH:         " + std::string(orig_SSL_read ? "OK" : "MISS (SChannel?)"));
    Log("SSL_read_ex MH:      " + std::string(orig_SSL_read_ex ? "OK" : "MISS"));
    (void)sigPatched;
    Log("CreateFileW IAT:     " + std::string(orig_CreateFileW ? "OK" : "MISS"));
    Log("CreateFileMappingW:  " + std::string(orig_CreateFileMappingW ? "OK" : "MISS"));
    Log("MapViewOfFile:       " + std::string(orig_MapViewOfFile ? "OK" : "MISS"));
    Log("UnmapViewOfFile:     " + std::string(orig_UnmapViewOfFile ? "OK" : "MISS"));
    Log("QueryFullProcImage:  " + std::string(orig_QueryFullProcessImageNameW ? "OK" : "MISS") + " (log-only, MapViewOfFile handles bypass)");
    Log("VirtualProtect:      " + std::string(orig_VirtualProtect ? "OK" : "MISS"));
    Log("recv:                " + std::string(orig_recv ? "OK" : "MISS"));
    Log("WSARecv:             " + std::string(orig_WSARecv ? "OK" : "MISS"));
    Log("WSASend:             " + std::string(orig_WSASend ? "OK" : "MISS"));
    Log("connect:             " + std::string(orig_connect ? "OK" : "MISS"));
    Log("send:                " + std::string(orig_send ? "OK" : "MISS"));
    Log("BCryptVerifySig:     " + std::string(orig_BCryptVerifySignature ? "OK" : "MISS"));
    Log("EVP_DigestVerifyFin: " + std::string(orig_EVP_DigestVerifyFinal ? "OK" : "MISS"));
    Log("ED25519_verify:      " + std::string(orig_ED25519_verify ? "OK" : "MISS"));
    Log("SodiumVerify MH:     " + std::string(g_sodiumVerifyAddr ? "OK" : "MISS"));
    Log("SigVerifyFunc HWBP:  " + std::string(g_hwbpTarget2 ? "OK" : "MISS (pattern not found)"));
    Log("PubkeyGetter MH:     " + std::string(g_keyGetterHooked ? "OK" : "MISS"));
    Log("DecryptMessage:      " + std::string(orig_DecryptMessage ? "OK" : "MISS"));
    Log("MessageBoxA/W:       " + std::string(orig_MessageBoxA ? "OK" : "MISS"));
    Log("exit/_exit/abort:    " + std::string(orig_exit ? "OK" : "MISS"));
    Log("terminate:           " + std::string(orig_terminate ? "OK" : "MISS"));
    Log("CreateThread:        " + std::string(orig_CreateThread ? "OK" : "MISS"));
    Log("WaitForSingleObject: " + std::string(orig_WaitForSingleObject ? "OK" : "MISS"));
    Log("Sleep:               " + std::string(orig_Sleep ? "OK" : "MISS"));
    Log("GetProcAddress:      " + std::string(orig_GetProcAddress ? "OK" : "MISS"));
    Log("RegQueryValueExW:    " + std::string(orig_RegQueryValueExW ? "OK" : "MISS"));
    Log("NtGetContextThread:  " + std::string(orig_NtGetContextThread ? "OK" : "MISS"));
    Log("NtSetContextThread:  " + std::string(orig_NtSetContextThread ? "OK" : "MISS"));
    Log("=== Init complete ===");

    HANDLE hScan = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    if (hScan) CloseHandle(hScan);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        InitLog(hMod);
        HANDLE h = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    else if (reason == DLL_PROCESS_DETACH && lpReserved == nullptr) {
        if (g_vehHandle) {
            RemoveVectoredExceptionHandler(g_vehHandle);
            g_vehHandle = nullptr;
        }
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}

// Made by Ivan Kozlovsky - https://ivankozlovsky.com - contact@ivankozlovsky.com