#pragma once
#include <windows.h>
#include <functional>
#include <string>
#include <vector>
#include "trust.h"

namespace lg {

struct AppEntry {
    std::wstring path;
    std::wstring display;
    int          layer = 0;           // Windows components start in layer 12, everything else in 0
    TrustInfo    trust;               // latest signature verdict (re-checked live)
    TrustClass   approved = TrustClass::Unsigned;  // verdict at the moment the layer was granted
    HANDLE       hProc = nullptr;
    DWORD        pid = 0;
    bool Running() const { return hProc != nullptr; }
};

enum class AuthResult { Ok, BadPassword, Cancelled, Locked, NoPassword, Error };
enum class ChangeResult { Granted, DeniedPolicy, DeniedAuth, Cancelled, Locked, Error };

class LayerManager {
public:
    bool Init(HINSTANCE hInst);

    // ---- password / anti-phishing phrase ----------------------------------
    bool HasPassword() const { return hasPassword_; }
    bool FirstRunSetup(std::wstring& phraseOut, std::wstring& err);

    // Freeze third-party processes -> secure desktop prompt -> verify. While
    // everything is still frozen `onSuccess` runs, then the processes are thawed.
    AuthResult Authenticate(const std::wstring& purpose, std::wstring& msg,
                            const std::function<void()>& onSuccess = nullptr);

    // ---- applications ---------------------------------------------------------
    std::vector<AppEntry>& Apps() { return apps_; }
    bool AddApp(const std::wstring& path, std::wstring* summary = nullptr);
    void RemoveApp(size_t idx);
    ChangeResult ChangeLayer(size_t idx, int newLayer, std::wstring& msg);
    bool Launch(size_t idx, std::wstring& err);
    void Stop(size_t idx);
    bool RefreshProcessState();        // true if any running/stopped status changed
    // Real-time check: re-verifies every app (cheap, cached per file version).
    // An app whose signature got WORSE since it was approved is dropped to layer 0.
    // Returns true if anything changed; `report` lists what happened.
    bool RescanTrust(std::wstring* report = nullptr);

private:
    bool LoadAuth();
    bool VerifyPassword(const wchar_t* pw) const;
    void LoadApps();
    void SaveApps() const;
    bool Demote(AppEntry& a, const wchar_t* why);

    HINSTANCE hInst_ = nullptr;
    bool hasPassword_ = false;
    unsigned char salt_[16] = {};
    unsigned char hash_[32] = {};
    unsigned long iter_ = 0;
    std::wstring phrase_;
    int fails_ = 0;
    ULONGLONG lockedUntil_ = 0;
    std::vector<AppEntry> apps_;
};

} // namespace lg
