#include "procmon.h"
#include "sandbox.h"
#include <tlhelp32.h>
#include <map>
#include <set>

namespace lg {
namespace {

std::wstring BaseOf(const std::wstring& p)
{
    size_t i = p.find_last_of(L"\\/");
    return i == std::wstring::npos ? p : p.substr(i + 1);
}

bool SameFileTime(const FILETIME& a, const FILETIME& b)
{
    return a.dwHighDateTime == b.dwHighDateTime && a.dwLowDateTime == b.dwLowDateTime;
}

} // namespace

bool ProcMonitor::Start(HWND notify, UINT msg)
{
    if (th_.joinable()) return true;
    hwnd_ = notify;
    msg_ = msg;
    stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_) return false;
    th_ = std::thread([this] { Run(); });
    return true;
}

void ProcMonitor::Stop()
{
    if (!th_.joinable()) return;
    SetEvent(stop_);
    th_.join();
    CloseHandle(stop_);
    stop_ = nullptr;
}

void ProcMonitor::Run()
{
    std::set<DWORD> known;
    bool first = true;
    const DWORD self = GetCurrentProcessId();

    do {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            std::set<DWORD> current;
            std::map<DWORD, PROCESSENTRY32W> fresh;

            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);
            for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
                current.insert(pe.th32ProcessID);
                if (!first && !known.count(pe.th32ProcessID)) fresh[pe.th32ProcessID] = pe;
            }
            CloseHandle(snap);
            known.swap(current);
            first = false;                      // the very first scan is only the baseline

            for (auto& kv : fresh) {
                const PROCESSENTRY32W& p = kv.second;
                if (p.th32ProcessID == 0 || p.th32ProcessID == 4 || p.th32ProcessID == self) continue;

                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.th32ProcessID);
                if (!h) continue;               // protected process or already gone

                wchar_t path[2048] = {};
                DWORD len = _countof(path);
                if (!QueryFullProcessImageNameW(h, 0, path, &len) || len == 0) { CloseHandle(h); continue; }

                auto* ev = new ProcEvent();
                ev->pid = p.th32ProcessID;
                ev->ppid = p.th32ParentProcessID;
                ev->name = p.szExeFile;
                ev->path = path;
                ev->id = nextId_++;
                FILETIME ct = {}, et = {}, kt = {}, ut = {};
                if (GetProcessTimes(h, &ct, &et, &kt, &ut)) ev->created = ct;
                ev->sandboxed = InLayerJob(h);
                CloseHandle(h);

                if (!ev->sandboxed) ev->trust = EvaluateTrust(ev->path);   // WinVerifyTrust runs off the UI thread
                if (ev->name.empty()) ev->name = BaseOf(ev->path);

                if (!PostMessageW(hwnd_, msg_, 0, reinterpret_cast<LPARAM>(ev))) delete ev;
            }
        }
    } while (WaitForSingleObject(stop_, 400) == WAIT_TIMEOUT);
}

bool TerminateIfSame(const ProcEvent& ev)
{
    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ev.pid);
    if (!h) return false;
    FILETIME ct = {}, et = {}, kt = {}, ut = {};
    bool same = GetProcessTimes(h, &ct, &et, &kt, &ut) && SameFileTime(ct, ev.created);
    bool ok = same && TerminateProcess(h, 1) != FALSE;
    CloseHandle(h);
    return ok;
}

} // namespace lg
