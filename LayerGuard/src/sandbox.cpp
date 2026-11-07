#include "sandbox.h"
#include "layers.h"
#include "audit.h"
#include <userenv.h>
#include <sddl.h>
#include <mutex>

namespace lg {
namespace {

std::mutex g_jobMu;
HANDLE     g_jobs[LG_LAYER_COUNT] = {};

std::wstring Err(const wchar_t* what, DWORD e = GetLastError())
{
    wchar_t b[48];
    swprintf_s(b, L" (error %lu)", e);
    return std::wstring(what) + b;
}

// One Job Object per layer, shared by every app in that layer. This is what
// makes layer 0 a *shared* sandbox: one memory/process/CPU budget for all.
HANDLE GetLayerJob(const LgLayer* L)
{
    std::lock_guard<std::mutex> lk(g_jobMu);
    if (g_jobs[L->id]) return g_jobs[L->id];

    wchar_t name[64];
    swprintf_s(name, L"Local\\LayerGuard.Job.%d", L->id);
    HANDLE job = CreateJobObjectW(nullptr, name);
    if (!job) return nullptr;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = {};
    DWORD f = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (L->memMB)    { f |= JOB_OBJECT_LIMIT_PROCESS_MEMORY; lim.ProcessMemoryLimit = (SIZE_T)L->memMB << 20; }
    if (L->maxProcs) { f |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS; lim.BasicLimitInformation.ActiveProcessLimit = L->maxProcs; }
    if (L->id <= 3)  { f |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; }   // untrusted tiers die with the manager
    lim.BasicLimitInformation.LimitFlags = f;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof(lim));

    if (L->cpuPct && L->cpuPct < 100) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION c = {};
        c.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        c.CpuRate = L->cpuPct * 100;              // 1/100 of a percent units
        SetInformationJobObject(job, JobObjectCpuRateControlInformation, &c, sizeof(c));
    }

    if (!(L->flags & LG_F_UI_FULL)) {
        JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {};
        ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS |
                                 JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_HANDLES |
                                 JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
        if (!(L->flags & LG_F_CLIPBOARD))
            ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui));
    }

    g_jobs[L->id] = job;
    return job;
}

std::wstring DirOf(const std::wstring& p)
{
    size_t i = p.find_last_of(L"\\/");
    return i == std::wstring::npos ? L"." : p.substr(0, i);
}

// ---- layers 0-3: AppContainer ------------------------------------------------
bool LaunchAppContainer(const LgLayer* L, const std::wstring& exe, PROCESS_INFORMATION& pi, std::wstring& err)
{
    wchar_t name[48];
    swprintf_s(name, L"LayerGuard.L%d", L->id);

    PSID acSid = nullptr;
    HRESULT hr = CreateAppContainerProfile(name, name, L"LayerGuard sandbox layer", nullptr, 0, &acSid);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        hr = DeriveAppContainerSidFromAppContainerName(name, &acSid);
    if (FAILED(hr)) { err = Err(L"AppContainer profile failed", (DWORD)hr); return false; }

    // No capabilities = no network, no user files. Layer 3 adds internetClient.
    PSID netSid = nullptr;
    SID_AND_ATTRIBUTES caps[1] = {};
    DWORD capCount = 0;
    if (L->flags & LG_F_NET) {
        if (ConvertStringSidToSidW(L"S-1-15-3-1", &netSid)) {   // internetClient
            caps[0].Sid = netSid;
            caps[0].Attributes = SE_GROUP_ENABLED;
            capCount = 1;
        }
    }

    SECURITY_CAPABILITIES sc = {};
    sc.AppContainerSid = acSid;
    sc.Capabilities = capCount ? caps : nullptr;
    sc.CapabilityCount = capCount;

    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    auto* attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    bool ok = false;
    if (attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        if (UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                      &sc, sizeof(sc), nullptr, nullptr)) {
            STARTUPINFOEXW si = {};
            si.StartupInfo.cb = sizeof(si);
            si.lpAttributeList = attrs;
            std::wstring cmd = L"\"" + exe + L"\"";
            std::wstring cwd = DirOf(exe);
            ok = CreateProcessW(exe.c_str(), &cmd[0], nullptr, nullptr, FALSE,
                                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
                                nullptr, cwd.c_str(), &si.StartupInfo, &pi) != FALSE;
            if (!ok) err = Err(L"CreateProcess (AppContainer) failed");
        } else {
            err = Err(L"UpdateProcThreadAttribute failed");
        }
        DeleteProcThreadAttributeList(attrs);
    }
    if (attrs) HeapFree(GetProcessHeap(), 0, attrs);
    if (netSid) LocalFree(netSid);
    FreeSid(acSid);
    return ok;
}

// ---- layers 4-14: restricted token --------------------------------------------
bool SetTokenIntegrity(HANDLE tok, DWORD rid)
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID sid = nullptr;
    if (!AllocateAndInitializeSid(&auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &sid)) return false;
    TOKEN_MANDATORY_LABEL tml = {};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = sid;
    BOOL r = SetTokenInformation(tok, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(sid));
    FreeSid(sid);
    return r != FALSE;
}

bool LaunchWithToken(const LgLayer* L, const std::wstring& exe, PROCESS_INFORMATION& pi, std::wstring& err)
{
    HANDLE self = nullptr, tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &self)) {
        err = Err(L"OpenProcessToken failed");
        return false;
    }
    // Strip every privilege; for Medium/Low tiers also drop the admin group
    // (LUA_TOKEN turns Administrators into deny-only).
    DWORD flags = DISABLE_MAX_PRIVILEGE;
    if (L->iso == LG_ISO_RESTRICTED) flags |= LUA_TOKEN;
    BOOL ok = CreateRestrictedToken(self, flags, 0, nullptr, 0, nullptr, 0, nullptr, &tok);
    CloseHandle(self);
    if (!ok) { err = Err(L"CreateRestrictedToken failed"); return false; }

    if (L->iso == LG_ISO_RESTRICTED && !SetTokenIntegrity(tok, L->integrityRid)) {
        err = Err(L"Setting integrity level failed");
        CloseHandle(tok);
        return false;
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    std::wstring cmd = L"\"" + exe + L"\"";
    std::wstring cwd = DirOf(exe);
    ok = CreateProcessAsUserW(tok, exe.c_str(), &cmd[0], nullptr, nullptr, FALSE,
                              CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
                              nullptr, cwd.c_str(), &si, &pi);
    if (!ok) err = Err(L"CreateProcessAsUser failed");
    CloseHandle(tok);
    return ok != FALSE;
}

} // namespace

bool InLayerJob(HANDLE hProcess)
{
    std::lock_guard<std::mutex> lk(g_jobMu);
    for (HANDLE job : g_jobs) {
        BOOL in = FALSE;
        if (job && IsProcessInJob(hProcess, job, &in) && in) return true;
    }
    return false;
}

LaunchResult LaunchInLayer(const std::wstring& exe, int layer)
{
    LaunchResult r;
    const LgLayer* L = LgGetLayer(layer);
    if (!L) { r.error = L"Invalid layer."; return r; }
    if (L->iso == LG_ISO_RESERVED) {
        r.error = L"Layer 15 is reserved for the kernel; applications cannot run in it.";
        return r;
    }
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        r.error = Err(L"Executable not found");
        return r;
    }
    HANDLE job = GetLayerJob(L);
    if (!job) { r.error = Err(L"Could not create the layer's Job Object"); return r; }

    PROCESS_INFORMATION pi = {};
    bool ok = (L->iso == LG_ISO_APPCONTAINER) ? LaunchAppContainer(L, exe, pi, r.error)
                                              : LaunchWithToken(L, exe, pi, r.error);
    if (!ok) return r;

    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        r.error = Err(L"AssignProcessToJobObject failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return r;
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    r.ok = true;
    r.pid = pi.dwProcessId;
    r.hProcess = pi.hProcess;
    LgAuditWrite(L"LAUNCH pid=%lu layer=%d (%s) exe=%s", r.pid, layer, L->name, exe.c_str());
    return r;
}

} // namespace lg
