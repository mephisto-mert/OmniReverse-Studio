// Self-Contained x64 MinHook Implementation for OmniReverse Studio (Header-Only)
// Uses 5-byte E9 rel32 detours with nearby page allocation (±2GB) + RIP-relative relocation + 14-byte fallback.

#pragma once
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <mutex>

#define MH_ALL_HOOKS NULL

typedef enum MH_STATUS {
    MH_UNKNOWN = -1,
    MH_OK = 0,
    MH_ERROR_ALREADY_INITIALIZED,
    MH_ERROR_NOT_INITIALIZED,
    MH_ERROR_ALREADY_CREATED,
    MH_ERROR_NOT_CREATED,
    MH_ERROR_ENABLED,
    MH_ERROR_DISABLED,
    MH_ERROR_NOT_EXECUTABLE,
    MH_ERROR_UNSUPPORTED_FUNCTION,
    MH_ERROR_MEMORY_ALLOC,
    MH_ERROR_MEMORY_PROTECT
} MH_STATUS;

namespace OmniMinHook {
    struct HookEntry {
        uint8_t* target;
        uint8_t* detour;
        uint8_t* trampoline;
        uint8_t  origBytes[32];
        size_t   patchLen;
        bool     useRel32;
        uint8_t* relayStub;
        bool     enabled;
    };

    static std::vector<HookEntry>& GetHooks() {
        static std::vector<HookEntry> s_hooks;
        return s_hooks;
    }
    static std::mutex& GetMutex() {
        static std::mutex s_mtx;
        return s_mtx;
    }

    static uint8_t* AllocSlotNear(uint8_t* origin) {
        static uint8_t* s_currBlock = nullptr;
        static size_t   s_used = 0;
        if (s_currBlock && s_used + 128 <= 4096) {
            int64_t diff = (int64_t)(s_currBlock + s_used) - (int64_t)origin;
            if (diff >= -0x7FFF0000LL && diff <= 0x7FFF0000LL) {
                uint8_t* ret = s_currBlock + s_used;
                s_used += 128;
                return ret;
            }
        }
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        uint64_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        uint64_t base = ((uint64_t)origin) & ~(gran - 1);
        for (uint64_t off = gran; off < 0x70000000ULL; off += gran) {
            for (int dir = -1; dir <= 1; dir += 2) {
                uint64_t cand = (dir < 0) ? (base > off ? base - off : 0) : (base + off);
                if (!cand) continue;
                void* p = VirtualAlloc((void*)cand, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) {
                    s_currBlock = (uint8_t*)p;
                    s_used = 128;
                    return s_currBlock;
                }
            }
        }
        return (uint8_t*)VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    static size_t DecodeInsnX64(const uint8_t* p, int* outRipDispOffset = nullptr) {
        if (outRipDispOffset) *outRipDispOffset = -1;
        size_t len = 0;
        bool opSize16 = false;
        uint8_t rex = 0;
        while (len < 15) {
            uint8_t b = p[len];
            if (b == 0x66) { opSize16 = true; len++; }
            else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                     b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65) len++;
            else if (b >= 0x40 && b <= 0x4F) { rex = b; len++; }
            else break;
        }
        uint8_t op = p[len++];
        if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0xC3 || op == 0xCC || op == 0xC9 || op == 0xF4)
            return len;
        if (op == 0xE8 || op == 0xE9) {
            if (outRipDispOffset) *outRipDispOffset = (int)len;
            return len + 4;
        }
        if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) return len + 1;
        if (op >= 0xB0 && op <= 0xB7) return len + 1;
        if (op >= 0xB8 && op <= 0xBF) return len + ((rex & 0x08) ? 8 : (opSize16 ? 2 : 4));
        if (op == 0x68) return len + 4;
        if (op == 0x6A) return len + 1;
        if (op == 0xC2) return len + 2;

        bool twoByte = false;
        if (op == 0x0F) {
            twoByte = true;
            op = p[len++];
            if (op >= 0x80 && op <= 0x8F) {
                if (outRipDispOffset) *outRipDispOffset = (int)len;
                return len + 4;
            }
            if (op == 0x05 || op == 0x31 || op == 0xA2) return len;
        }

        uint8_t modrm = p[len++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;

        if (mod != 3 && rm == 4) {
            uint8_t sib = p[len++];
            if (mod == 0 && (sib & 7) == 5) len += 4;
        }
        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) {
            if (outRipDispOffset) *outRipDispOffset = (int)len;
            len += 4;
        }

        if (!twoByte) {
            if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1 || op == 0xC6 || op == 0x6B) len += 1;
            else if (op == 0x81 || op == 0xC7 || op == 0x69) len += (opSize16 ? 2 : 4);
            else if (op == 0xF6 && (reg == 0 || reg == 1)) len += 1;
            else if (op == 0xF7 && (reg == 0 || reg == 1)) len += (opSize16 ? 2 : 4);
        } else {
            if (op == 0xBA || op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73) len += 1;
        }
        return len;
    }

    static void WriteAbsJump64(uint8_t* dst, void* target) {
        dst[0] = 0xFF; dst[1] = 0x25;
        *(uint32_t*)(dst + 2) = 0;
        *(uint64_t*)(dst + 6) = (uint64_t)target;
    }
}

static inline MH_STATUS WINAPI MH_Initialize(void) { return MH_OK; }
static inline MH_STATUS WINAPI MH_Uninitialize(void) { return MH_OK; }

static inline MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal) {
    if (!pTarget || !pDetour) return MH_ERROR_NOT_CREATED;
    std::lock_guard<std::mutex> lk(OmniMinHook::GetMutex());
    auto& hooks = OmniMinHook::GetHooks();
    for (auto& h : hooks) {
        if (h.target == (uint8_t*)pTarget) return MH_ERROR_ALREADY_CREATED;
    }

    uint8_t* t = (uint8_t*)pTarget;
    if (t[0] == 0xFF && t[1] == 0x25) {
        int32_t disp = *(int32_t*)(t + 2);
        uint8_t** indirect = (uint8_t**)(t + 6 + disp);
        if (indirect && *indirect) t = *indirect;
    }

    uint8_t* slot = OmniMinHook::AllocSlotNear(t);
    if (!slot) return MH_ERROR_MEMORY_ALLOC;

    uint8_t* relay = slot + 64;
    OmniMinHook::WriteAbsJump64(relay, pDetour);
    int64_t relDiff = (int64_t)relay - ((int64_t)t + 5);
    bool useRel32 = (relDiff >= -0x7FFFFFFFLL && relDiff <= 0x7FFFFFFFLL);
    size_t minBytes = useRel32 ? 5 : 14;

    size_t total = 0;
    while (total < minBytes) {
        int ripOff = -1;
        size_t l = OmniMinHook::DecodeInsnX64(t + total, &ripOff);
        if (l == 0) l = 1;
        memcpy(slot + total, t + total, l);
        if (ripOff >= 0) {
            int32_t oldDisp = *(int32_t*)(t + total + ripOff);
            uint8_t* targetAddr = (t + total + l) + oldDisp;
            int64_t newDisp = (int64_t)targetAddr - (int64_t)(slot + total + l);
            *(int32_t*)(slot + total + ripOff) = (int32_t)newDisp;
        }
        total += l;
    }

    OmniMinHook::WriteAbsJump64(slot + total, t + total);
    FlushInstructionCache(GetCurrentProcess(), slot, 128);

    OmniMinHook::HookEntry entry = {};
    entry.target = t;
    entry.detour = (uint8_t*)pDetour;
    entry.trampoline = slot;
    memcpy(entry.origBytes, t, total);
    entry.patchLen = total;
    entry.useRel32 = useRel32;
    entry.relayStub = relay;
    entry.enabled = false;
    hooks.push_back(entry);

    if (ppOriginal) *ppOriginal = (LPVOID)slot;
    return MH_OK;
}

static inline MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget) {
    std::lock_guard<std::mutex> lk(OmniMinHook::GetMutex());
    for (auto& h : OmniMinHook::GetHooks()) {
        if (pTarget != MH_ALL_HOOKS && h.target != (uint8_t*)pTarget) continue;
        if (h.enabled) continue;
        DWORD oldProt = 0;
        if (VirtualProtect(h.target, h.patchLen, PAGE_EXECUTE_READWRITE, &oldProt)) {
            if (h.useRel32) {
                h.target[0] = 0xE9;
                *(int32_t*)(h.target + 1) = (int32_t)((int64_t)h.relayStub - ((int64_t)h.target + 5));
                for (size_t i = 5; i < h.patchLen; i++) h.target[i] = 0x90;
            } else {
                OmniMinHook::WriteAbsJump64(h.target, h.detour);
                for (size_t i = 14; i < h.patchLen; i++) h.target[i] = 0x90;
            }
            VirtualProtect(h.target, h.patchLen, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), h.target, h.patchLen);
            h.enabled = true;
        }
    }
    return MH_OK;
}

static inline MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget) {
    std::lock_guard<std::mutex> lk(OmniMinHook::GetMutex());
    for (auto& h : OmniMinHook::GetHooks()) {
        if (pTarget != MH_ALL_HOOKS && h.target != (uint8_t*)pTarget) continue;
        if (!h.enabled) continue;
        DWORD oldProt = 0;
        if (VirtualProtect(h.target, h.patchLen, PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy(h.target, h.origBytes, h.patchLen);
            VirtualProtect(h.target, h.patchLen, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), h.target, h.patchLen);
            h.enabled = false;
        }
    }
    return MH_OK;
}
