#include "layermgr.h"
#include "layers.h"
#include "audit.h"
#include "paths.h"
#include "sandbox.h"
#include "procfreeze.h"
#include "securedesk.h"
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstddef>

namespace lg {
namespace {

constexpr unsigned long kIterations = 200000;      // PBKDF2-HMAC-SHA256
constexpr int  kMaxFails = 5;
constexpr ULONGLONG kLockMs = 60 * 1000;

const wchar_t* kWords[32] = {
    L"amber", L"harbor", L"copper", L"falcon", L"meadow", L"lantern", L"cobalt", L"juniper",
    L"granite", L"willow", L"saffron", L"horizon", L"pebble", L"thunder", L"orchid", L"compass",
    L"ember", L"glacier", L"maple", L"nebula", L"quartz", L"river", L"summit", L"tundra",
    L"velvet", L"walnut", L"zephyr", L"anchor", L"breeze", L"canyon", L"dolphin", L"echo"
};

std::string ToUtf8(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring FromUtf8(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

std::string Hex(const unsigned char* d, size_t n)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += hx[d[i] >> 4]; s += hx[d[i] & 15]; }
    return s;
}

bool UnHex(const std::string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = s[i * 2 + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else return false;
        }
        out[i] = (unsigned char)v;
    }
    return true;
}

bool Random(void* buf, ULONG n)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, (PUCHAR)buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool Pbkdf2(const wchar_t* pw, const unsigned char* salt, size_t saltLen, unsigned long iter,
            unsigned char* out, size_t outLen)
{
    BCRYPT_ALG_HANDLE h = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return false;
    std::string pwu = ToUtf8(pw);
    NTSTATUS st = BCryptDeriveKeyPBKDF2(h, (PUCHAR)pwu.data(), (ULONG)pwu.size(), (PUCHAR)salt,
                                        (ULONG)saltLen, iter, out, (ULONG)outLen, 0);
    SecureZeroMemory(&pwu[0], pwu.size());
    BCryptCloseAlgorithmProvider(h, 0);
    return BCRYPT_SUCCESS(st);
}

bool ConstTimeEq(const unsigned char* a, const unsigned char* b, size_t n)
{
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

std::wstring BaseName(const std::wstring& p)
{
    size_t i = p.find_last_of(L"\\/");
    return i == std::wstring::npos ? p : p.substr(i + 1);
}

} // namespace

// ---------------------------------------------------------------------------------
bool LayerManager::Init(HINSTANCE hInst)
{
    hInst_ = hInst;
    hasPassword_ = LoadAuth();
    LoadApps();
    return true;
}

bool LayerManager::LoadAuth()
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(L"auth.dat", path, MAX_PATH)) return false;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) return false;

    char line[512];
    std::string l[5];
    int n = 0;
    while (n < 5 && fgets(line, sizeof(line), f)) {
        std::string s = line;
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        l[n++] = s;
    }
    fclose(f);
    if (n < 5 || l[0] != "LGA1") return false;
    iter_ = strtoul(l[1].c_str(), nullptr, 10);
    if (iter_ < 100000) return false;                    // refuse downgraded files
    if (!UnHex(l[2], salt_, sizeof(salt_)) || !UnHex(l[3], hash_, sizeof(hash_))) return false;
    phrase_ = FromUtf8(l[4]);
    return true;
}

bool LayerManager::VerifyPassword(const wchar_t* pw) const
{
    unsigned char calc[32];
    if (!Pbkdf2(pw, salt_, sizeof(salt_), iter_, calc, sizeof(calc))) return false;
    bool ok = ConstTimeEq(calc, hash_, sizeof(calc));
    SecureZeroMemory(calc, sizeof(calc));
    return ok;
}

bool LayerManager::FirstRunSetup(std::wstring& phraseOut, std::wstring& err)
{
    // Random 3-word anti-phishing phrase, e.g. "amber-falcon-river".
    unsigned char r[3];
    if (!Random(r, sizeof(r))) { err = L"Random generator failed."; return false; }
    std::wstring phrase = std::wstring(kWords[r[0] & 31]) + L"-" + kWords[r[1] & 31] + L"-" + kWords[r[2] & 31];

    wchar_t pw1[128] = {}, pw2[128] = {};
    bool ok = false;
    {
        FreezeGuard guard(120);
        if (!SecurePasswordPrompt(hInst_, L"إنشاء كلمة المرور (Create password)",
                                  L"اختر كلمة مرور قوية (8 أحرف على الأقل). ستُطلب عند رفع أي طبقة.",
                                  phrase, pw1, _countof(pw1), 120)) {
            err = L"Setup cancelled.";
        } else if (wcslen(pw1) < 8) {
            err = L"The password must be at least 8 characters.";
        } else if (!SecurePasswordPrompt(hInst_, L"تأكيد كلمة المرور (Confirm password)",
                                         L"أعد إدخال كلمة المرور نفسها.", phrase, pw2, _countof(pw2), 120)) {
            err = L"Setup cancelled.";
        } else if (wcscmp(pw1, pw2) != 0) {
            err = L"The two passwords do not match.";
        } else {
            ok = true;
        }
    }
    if (ok) {
        iter_ = kIterations;
        if (!Random(salt_, sizeof(salt_)) ||
            !Pbkdf2(pw1, salt_, sizeof(salt_), iter_, hash_, sizeof(hash_))) {
            err = L"Key derivation failed.";
            ok = false;
        }
    }
    SecureZeroMemory(pw1, sizeof(pw1));
    SecureZeroMemory(pw2, sizeof(pw2));
    if (!ok) return false;

    wchar_t path[MAX_PATH];
    FILE* f = nullptr;
    if (!LgDataPath(L"auth.dat", path, MAX_PATH) || _wfopen_s(&f, path, L"wb") != 0 || !f) {
        err = L"Could not write auth.dat (run as Administrator).";
        return false;
    }
    fprintf(f, "LGA1\n%lu\n%s\n%s\n%s\n", iter_, Hex(salt_, sizeof(salt_)).c_str(),
            Hex(hash_, sizeof(hash_)).c_str(), ToUtf8(phrase).c_str());
    fclose(f);

    phrase_ = phrase;
    phraseOut = phrase;
    hasPassword_ = true;
    LgAuditWrite(L"SETUP password created");
    return true;
}

AuthResult LayerManager::Authenticate(const std::wstring& purpose, std::wstring& msg,
                                      const std::function<void()>& onSuccess)
{
    if (!hasPassword_) { msg = L"No password has been set up yet."; return AuthResult::NoPassword; }

    if (GetTickCount64() < lockedUntil_) {
        msg = L"Too many failed attempts. Try again in a minute.";
        LgAuditWrite(L"AUTH locked-out purpose=%s", purpose.c_str());
        return AuthResult::Locked;
    }

    FreezeGuard guard(90);          // thaws on every exit path, including exceptions

    wchar_t pw[128] = {};
    bool got = SecurePasswordPrompt(hInst_, L"تأكيد الهوية (Authentication required)",
                                    purpose, phrase_, pw, _countof(pw), 60);
    if (!got) {
        SecureZeroMemory(pw, sizeof(pw));
        msg = L"Cancelled.";
        LgAuditWrite(L"AUTH cancelled purpose=%s", purpose.c_str());
        return AuthResult::Cancelled;
    }

    bool ok = VerifyPassword(pw);
    SecureZeroMemory(pw, sizeof(pw));

    if (!ok) {
        fails_++;
        LgAuditWrite(L"AUTH failed attempt=%d purpose=%s", fails_, purpose.c_str());
        if (fails_ >= kMaxFails) {
            lockedUntil_ = GetTickCount64() + kLockMs;
            fails_ = 0;
            msg = L"Wrong password. Locked for one minute.";
            LgAuditWrite(L"AUTH lockout 60s");
        } else {
            Sleep(500u * (unsigned)fails_);          // growing delay against guessing
            msg = L"Wrong password.";
        }
        return AuthResult::BadPassword;
    }

    fails_ = 0;
    LgAuditWrite(L"AUTH ok purpose=%s", purpose.c_str());
    if (onSuccess) onSuccess();                      // still frozen here
    return AuthResult::Ok;
}

// ---- applications ----------------------------------------------------------------
void LayerManager::LoadApps()
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(L"apps.cfg", path, MAX_PATH)) return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rt, ccs=UTF-8") != 0 || !f) return;
    wchar_t line[1024];
    while (fgetws(line, 1024, f)) {
        std::wstring s = line;
        while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r')) s.pop_back();
        // new format: layer|approvedClass|path      old format: layer|path
        size_t b1 = s.find(L'|');
        if (b1 == std::wstring::npos) continue;
        size_t b2 = s.find(L'|', b1 + 1);
        int layer = _wtoi(s.substr(0, b1).c_str());
        if (layer < 0 || layer >= LG_LAYER_KERNEL) layer = 0;      // corrupt value -> safest tier
        AppEntry e;
        e.layer = layer;
        e.trust = EvaluateTrust(b2 == std::wstring::npos ? s.substr(b1 + 1) : s.substr(b2 + 1));
        e.approved = e.trust.cls;                                   // old format: trust what we see now
        if (b2 != std::wstring::npos) {
            int c = _wtoi(s.substr(b1 + 1, b2 - b1 - 1).c_str());
            if (c >= 0 && c <= 4) e.approved = static_cast<TrustClass>(c);
            e.path = s.substr(b2 + 1);
        } else {
            e.path = s.substr(b1 + 1);
        }
        e.display = BaseName(e.path);
        if (e.layer > 0 && Rank(e.trust.cls) > Rank(e.approved)) {  // file changed while we were off
            e.layer = 0;
            LgAuditWrite(L"TRUST demoted at startup app=%s now=%s", e.path.c_str(), e.trust.Text().c_str());
        }
        apps_.push_back(e);
    }
    fclose(f);
}

void LayerManager::SaveApps() const
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(L"apps.cfg", path, MAX_PATH)) return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"wt, ccs=UTF-8") != 0 || !f) return;
    for (const AppEntry& e : apps_) fwprintf(f, L"%d|%d|%s\n", e.layer, Rank(e.approved), e.path.c_str());
    fclose(f);
}

bool LayerManager::AddApp(const std::wstring& path, std::wstring* summary)
{
    for (const AppEntry& e : apps_)
        if (_wcsicmp(e.path.c_str(), path.c_str()) == 0) return false;
    AppEntry e;
    e.path = path;
    e.display = BaseName(path);
    e.trust = EvaluateTrust(path);                 // signature is checked right now
    e.approved = e.trust.cls;
    // Genuine Windows components start in the clean system layer; everything
    // else (new, downloaded, unsigned, third-party) starts in the sandbox.
    // The user can still change it manually afterwards.
    e.layer = SuggestedLayer(e.trust);
    apps_.push_back(e);
    SaveApps();
    LgAuditWrite(L"ADD app=%s layer=%d trust=%s publisher=%s status=0x%08lX",
                 path.c_str(), e.layer, e.trust.Text().c_str(), e.trust.publisher.c_str(),
                 (unsigned long)e.trust.status);
    if (summary) {
        *summary = L"التقييم / Verdict: " + e.trust.Text() + L"\n" +
                   L"الطبقة الابتدائية / Initial layer: " + std::to_wstring(e.layer) + L" — " +
                   LgGetLayer(e.layer)->name;
    }
    return true;
}

void LayerManager::RemoveApp(size_t idx)
{
    if (idx >= apps_.size()) return;
    Stop(idx);
    LgAuditWrite(L"REMOVE app=%s", apps_[idx].path.c_str());
    apps_.erase(apps_.begin() + (std::ptrdiff_t)idx);
    SaveApps();
}

ChangeResult LayerManager::ChangeLayer(size_t idx, int to, std::wstring& msg)
{
    if (idx >= apps_.size()) { msg = L"No such application."; return ChangeResult::Error; }
    AppEntry& a = apps_[idx];
    int from = a.layer;
    LgAuditWrite(L"REQUEST layer change app=%s from=%d to=%d", a.path.c_str(), from, to);

    LgPolicy p = LgCheckTransition(from, to);
    if (p != LG_POL_OK) {
        msg = LgPolicyText(p);
        LgAuditWrite(L"DENIED policy app=%s from=%d to=%d reason=%s", a.path.c_str(), from, to, msg.c_str());
        return ChangeResult::DeniedPolicy;
    }

    a.trust = EvaluateTrust(a.path);               // live verdict before the user decides

    auto apply = [&]() {
        a.layer = to;
        a.approved = a.trust.cls;
        SaveApps();
        LgAuditWrite(L"GRANTED app=%s from=%d to=%d", a.path.c_str(), from, to);
    };

    if (!LgNeedsAuth(from, to)) {                  // lowering privileges needs no secret
        apply();
        msg = L"Layer lowered.";
        return ChangeResult::Granted;
    }

    std::wstring detail = L"رفع «" + a.display + L"» من الطبقة " + std::to_wstring(from) + L" إلى " +
                          std::to_wstring(to) + L" (" + LgGetLayer(to)->name + L").\nالتوقيع: " + a.trust.Text();

    AuthResult r = Authenticate(detail, msg, apply);
    switch (r) {
    case AuthResult::Ok:          msg = L"Layer changed."; return ChangeResult::Granted;
    case AuthResult::Cancelled:   return ChangeResult::Cancelled;
    case AuthResult::Locked:      return ChangeResult::Locked;
    case AuthResult::BadPassword: LgAuditWrite(L"DENIED auth app=%s to=%d", a.path.c_str(), to);
                                  return ChangeResult::DeniedAuth;
    default:                      return ChangeResult::Error;
    }
}

bool LayerManager::Launch(size_t idx, std::wstring& err)
{
    if (idx >= apps_.size()) { err = L"No such application."; return false; }
    AppEntry& a = apps_[idx];
    if (a.Running()) return true;

    // Real-time check on every launch: the file may have been replaced since it was added.
    a.trust = EvaluateTrust(a.path);
    if (a.trust.cls == TrustClass::Missing) { err = L"The executable no longer exists."; return false; }
    if (a.layer > 0 && Rank(a.trust.cls) > Rank(a.approved)) {
        std::wstring why = L"التوقيع ساء منذ الموافقة: " + a.trust.Text();
        Demote(a, why.c_str());
        err = L"تم إنزال التطبيق إلى الطبقة 0 لأن توقيعه تغيّر / got worse since approval (" + a.trust.Text() +
              L"). لم يُشغَّل؛ شغّله مجدداً إن أردت (سيعمل في الطبقة 0).";
        return false;
    }
    LaunchResult r = LaunchInLayer(a.path, a.layer);
    if (!r.ok) { err = r.error; LgAuditWrite(L"LAUNCH failed app=%s: %s", a.path.c_str(), r.error.c_str()); return false; }
    a.hProc = r.hProcess;
    a.pid = r.pid;
    return true;
}

void LayerManager::Stop(size_t idx)
{
    if (idx >= apps_.size()) return;
    AppEntry& a = apps_[idx];
    if (!a.hProc) return;
    TerminateProcess(a.hProc, 1);
    LgAuditWrite(L"STOP pid=%lu app=%s", a.pid, a.path.c_str());
    CloseHandle(a.hProc);
    a.hProc = nullptr;
    a.pid = 0;
}

bool LayerManager::Demote(AppEntry& a, const wchar_t* why)
{
    int from = a.layer;
    a.layer = 0;
    a.approved = a.trust.cls;
    SaveApps();
    LgAuditWrite(L"TRUST demoted app=%s from=%d to=0 reason=%s", a.path.c_str(), from, why);
    return true;
}

bool LayerManager::RescanTrust(std::wstring* report)
{
    bool changed = false;
    for (AppEntry& a : apps_) {
        TrustInfo now = EvaluateTrust(a.path);
        bool different = now.cls != a.trust.cls || now.publisher != a.trust.publisher;
        a.trust = now;
        if (different) changed = true;
        if (a.layer > 0 && Rank(now.cls) > Rank(a.approved)) {
            std::wstring why = L"signature got worse: " + now.Text();
            Demote(a, why.c_str());
            if (report) *report += a.display + L" → layer 0 (" + now.Text() + L")\n";
            changed = true;
        }
    }
    return changed;
}

bool LayerManager::RefreshProcessState()
{
    bool changed = false;
    for (AppEntry& a : apps_) {
        if (a.hProc && WaitForSingleObject(a.hProc, 0) == WAIT_OBJECT_0) {
            CloseHandle(a.hProc);
            a.hProc = nullptr;
            a.pid = 0;
            changed = true;
        }
    }
    return changed;
}

} // namespace lg
