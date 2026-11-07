#pragma once
#include <windows.h>
#include <cstddef>

namespace lg {

// Suspends every third-party process in the current session (never LayerGuard
// itself, never anything under %WINDIR%, never the shell/compositor/AV in the
// exclusion list). A watchdog thaws everything after `watchdogSeconds` even if
// the UI hangs, so a crash can never leave the user with a frozen desktop.
// Returns the number of processes suspended.
size_t FreezeThirdParty(unsigned watchdogSeconds);

// Resumes everything suspended by FreezeThirdParty. Idempotent.
void ThawAll();

bool IsFrozen();

// RAII: freeze on construction, thaw on destruction (also on early return).
struct FreezeGuard {
    size_t count;
    explicit FreezeGuard(unsigned watchdogSeconds = 90) : count(FreezeThirdParty(watchdogSeconds)) {}
    ~FreezeGuard() { ThawAll(); }
    FreezeGuard(const FreezeGuard&) = delete;
    FreezeGuard& operator=(const FreezeGuard&) = delete;
};

} // namespace lg
