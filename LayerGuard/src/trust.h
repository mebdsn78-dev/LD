#pragma once
#include <windows.h>
#include <string>

namespace lg {

// How much we know about an executable, from its digital signature.
// The numeric order is a "risk rank": a bigger value is worse.
enum class TrustClass {
    System      = 0,   // genuine Windows component (see IsWindowsComponent)
    SignedValid = 1,   // valid Authenticode signature by some publisher
    Unsigned    = 2,   // no signature at all
    Invalid     = 3,   // has a signature that does NOT verify (modified / untrusted chain)
    Missing     = 4    // file not found
};

struct TrustInfo {
    TrustClass   cls = TrustClass::Missing;
    std::wstring publisher;      // signer's display name (when available)
    bool         catalog = false;// signed through a Windows catalog (.cat), not embedded
    LONG         status = 0;     // raw WinVerifyTrust result, for the audit log

    std::wstring Text() const;   // short label for the UI / password prompt
};

constexpr int kDefaultLayer = 0;     // new, unknown, unsigned, third-party  -> sandbox
constexpr int kSystemLayer  = 12;    // genuine Windows tools                -> "clean" layer

inline int  Rank(TrustClass c) { return static_cast<int>(c); }
inline int  SuggestedLayer(const TrustInfo& t) { return t.cls == TrustClass::System ? kSystemLayer : kDefaultLayer; }

// Verifies the file right now. Results are cached per (path, size, last-write
// time), so calling this often is cheap, yet any change to the file on disk
// forces a fresh verification.
//
// A file is classed System only when ALL of these hold:
//   1. its Authenticode signature (embedded or Windows catalog) verifies,
//   2. the signer's name starts with "Microsoft",
//   3. its real path (after resolving links) is inside the Windows directory,
//   4. its owner is NT SERVICE\TrustedInstaller (so no ordinary admin or
//      user could have dropped it there).
TrustInfo EvaluateTrust(const std::wstring& path);

} // namespace lg
