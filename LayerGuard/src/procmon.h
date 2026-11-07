#pragma once
#include <windows.h>
#include <atomic>
#include <string>
#include <thread>
#include "trust.h"

namespace lg {

// One newly started process, evaluated by the real-time monitor.
struct ProcEvent {
    DWORD        pid = 0;
    DWORD        ppid = 0;
    FILETIME     created = {};      // used to make sure a PID was not reused before we act on it
    std::wstring name;
    std::wstring path;
    TrustInfo    trust;
    bool         sandboxed = false; // started by LayerGuard (inside one of its Job Objects)
    ULONGLONG    id = 0;
};

// Real-time process monitor. A worker thread watches the process list
// (every 400 ms), and for each NEW process reads its image path, verifies its
// signature and posts a ProcEvent to `notify` as message `msg`
// (LPARAM = heap-allocated ProcEvent*, the receiver must `delete` it).
//
// Honest limits: this is detection after the fact, not interception. Very
// short-lived processes (<400 ms) can be missed, and the process has already
// started when the verdict arrives. Pre-execution blocking needs a kernel
// driver (PsSetCreateProcessNotifyRoutineEx) or WDAC/AppLocker.
class ProcMonitor {
public:
    ~ProcMonitor() { Stop(); }
    bool Start(HWND notify, UINT msg);
    void Stop();

private:
    void Run();

    HWND              hwnd_ = nullptr;
    UINT              msg_ = 0;
    std::thread       th_;
    HANDLE            stop_ = nullptr;
    std::atomic<ULONGLONG> nextId_{ 1 };
};

// Terminates `ev.pid` only if it is still the same process (creation time matches).
bool TerminateIfSame(const ProcEvent& ev);

} // namespace lg
