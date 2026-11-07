#pragma once
#include <windows.h>
#include <string>

namespace lg {

struct LaunchResult {
    bool         ok = false;
    DWORD        pid = 0;
    HANDLE       hProcess = nullptr;   // caller owns it
    std::wstring error;
};

// Starts `exe` inside the isolation profile of `layer` (see layers.c):
//   0-3   AppContainer (+ capabilities per layer) inside the layer's shared Job
//   4-11  restricted token, Medium/Low integrity, privileges stripped
//   12-14 High integrity, privileges stripped
//   15    refused
// The process is created suspended, put into the layer's Job Object and only
// then resumed, so it never runs a single instruction outside its limits.
LaunchResult LaunchInLayer(const std::wstring& exe, int layer);

} // namespace lg

namespace lg {
// True if the process lives in any of LayerGuard's per-layer Job Objects
// (i.e. it was started by LayerGuard, or is a descendant of such a process).
bool InLayerJob(HANDLE hProcess);
}
