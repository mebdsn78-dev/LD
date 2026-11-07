#include "procfreeze.h"
#include "audit.h"
#include <tlhelp32.h>
#include <mutex>
#include <vector>
#include <thread>
#include <string>

namespace lg {
namespace {

typedef LONG (NTAPI* NtProc_t)(HANDLE);

struct Frozen { DWORD pid; HANDLE h; };   // the open handle also pins the PID against reuse

std::mutex          g_mu;
std::vector<Frozen> g_frozen;
HANDLE              g_cancel = nullptr;
unsigned            g_gen = 0;

NtProc_t Resolve(const char* name)
{
    HMODULE m = GetModuleHandleW(L"ntdll.dll");
    return m ? reinterpret_cast<NtProc_t>(GetProcAddress(m, name)) : nullptr;
}

bool Excluded(const wchar_t* exe)
{
    static const wchar_t* kSkip[] = {
        L"explorer.exe", L"dwm.exe", L"csrss.exe", L"winlogon.exe", L"services.exe",
        L"lsass.exe", L"svchost.exe", L"sihost.exe", L"ctfmon.exe", L"fontdrvhost.exe",
        L"textinputhost.exe", L"runtimebroker.exe", L"taskhostw.exe", L"audiodg.exe",
        L"startmenuexperiencehost.exe", L"shellexperiencehost.exe", L"searchhost.exe",
        L"msmpeng.exe", L"nissrv.exe", L"securityhealthservice.exe", L"securityhealthsystray.exe"
    };
    for (const wchar_t* s : kSkip)
        if (_wcsicmp(exe, s) == 0) return true;
    return false;
}

// Caller holds g_mu.
void ThawLocked()
{
    if (g_frozen.empty() && !g_cancel) return;
    NtProc_t resume = Resolve("NtResumeProcess");
    size_t n = g_frozen.size();
    for (const Frozen& f : g_frozen) {
        if (resume) resume(f.h);
        CloseHandle(f.h);
    }
    g_frozen.clear();
    if (g_cancel) {
        SetEvent(g_cancel);          // wakes the watchdog, which owns its own duplicate
        CloseHandle(g_cancel);
        g_cancel = nullptr;
    }
    if (n) LgAuditWrite(L"THAW resumed=%zu", n);
}

void WatchdogThaw(unsigned gen)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (gen == g_gen && !g_frozen.empty()) {
        LgAuditWrite(L"WATCHDOG forced thaw after timeout");
        ThawLocked();
    }
}

} // namespace

size_t FreezeThirdParty(unsigned watchdogSeconds)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_frozen.empty()) return g_frozen.size();

    NtProc_t suspend = Resolve("NtSuspendProcess");
    if (!suspend) return 0;

    wchar_t winDir[MAX_PATH] = {};
    UINT winLen = GetWindowsDirectoryW(winDir, MAX_PATH);

    DWORD mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        DWORD pid = pe.th32ProcessID;
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;

        DWORD sess = 0;
        if (!ProcessIdToSessionId(pid, &sess) || sess != mySession || sess == 0) continue;
        if (Excluded(pe.szExeFile)) continue;

        HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) continue;                                   // protected or already gone

        wchar_t path[MAX_PATH] = {};
        DWORD len = MAX_PATH;
        bool system = false;
        if (QueryFullProcessImageNameW(h, 0, path, &len) && winLen &&
            _wcsnicmp(path, winDir, winLen) == 0)
            system = true;                                  // Microsoft binaries under %WINDIR%
        if (system) { CloseHandle(h); continue; }

        if (suspend(h) == 0) g_frozen.push_back({ pid, h });
        else CloseHandle(h);
    }
    CloseHandle(snap);

    if (g_frozen.empty()) return 0;

    // Watchdog: thaw automatically if nobody does it within the timeout.
    g_cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE mine = nullptr;
    DuplicateHandle(GetCurrentProcess(), g_cancel, GetCurrentProcess(), &mine, 0, FALSE, DUPLICATE_SAME_ACCESS);
    unsigned gen = ++g_gen;
    if (mine) {
        std::thread([mine, gen, watchdogSeconds]() {
            DWORD r = WaitForSingleObject(mine, watchdogSeconds * 1000);
            CloseHandle(mine);
            if (r == WAIT_TIMEOUT) WatchdogThaw(gen);
        }).detach();
    }

    LgAuditWrite(L"FREEZE suspended=%zu watchdog=%us", g_frozen.size(), watchdogSeconds);
    return g_frozen.size();
}

void ThawAll()
{
    std::lock_guard<std::mutex> lk(g_mu);
    ThawLocked();
}

bool IsFrozen()
{
    std::lock_guard<std::mutex> lk(g_mu);
    return !g_frozen.empty();
}

} // namespace lg
