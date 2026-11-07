#include "trust.h"
// Order matters: with WIN32_LEAN_AND_MEAN, wincrypt.h must come BEFORE wintrust/mscat/softpub.
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <cwctype>
#include <map>
#include <mutex>
#include <vector>

namespace lg {

std::wstring TrustInfo::Text() const
{
    switch (cls) {
    case TrustClass::System:      return L"نظام Windows ✔ (Microsoft)";
    case TrustClass::SignedValid: return L"موقّع ✔: " + (publisher.empty() ? std::wstring(L"?") : publisher);
    case TrustClass::Unsigned:    return L"غير موقّع (Unsigned)";
    case TrustClass::Invalid:     return L"توقيع غير صالح ✘ (Invalid)";
    case TrustClass::Missing:     return L"الملف غير موجود (Missing)";
    }
    return L"?";
}

namespace {

// WinVerifyTrust wants an HWND; INVALID_HANDLE_VALUE means "no UI".
const HWND kNoWnd = reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);

std::mutex g_mu;
std::map<std::wstring, TrustInfo> g_cache;

std::wstring SignerName(HANDLE stateData)
{
    CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(stateData);
    if (!pd) return L"";
    CRYPT_PROVIDER_SGNR* s = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
    if (!s) return L"";
    CRYPT_PROVIDER_CERT* c = WTHelperGetProvCertFromChain(s, 0);
    if (!c || !c->pCert) return L"";
    wchar_t name[256] = {};
    if (!CertGetNameStringW(c->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256)) return L"";
    return name;
}

// No network access: no revocation download, cached URLs only.
void InitWintrustData(WINTRUST_DATA& wd)
{
    wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
}

// Embedded Authenticode signature.
LONG VerifyEmbedded(const std::wstring& path, std::wstring& publisher)
{
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd;
    InitWintrustData(wd);
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(kNoWnd, &action, &wd);
    if (st == 0) publisher = SignerName(wd.hWVTStateData);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(kNoWnd, &action, &wd);
    return st;
}

// Windows components (cmd.exe, ping.exe, ...) are normally signed through
// catalog files, not embedded signatures.
LONG VerifyCatalog(const std::wstring& path, std::wstring& publisher)
{
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return TRUST_E_NOSIGNATURE;

    LONG result = TRUST_E_NOSIGNATURE;
    const wchar_t* algs[2] = { BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM };

    for (int pass = 0; pass < 2 && result != 0; ++pass) {
        HCATADMIN adm = nullptr;
        if (!CryptCATAdminAcquireContext2(&adm, nullptr, algs[pass], nullptr, 0)) continue;

        DWORD cb = 0;
        CryptCATAdminCalcHashFromFileHandle2(adm, hf, &cb, nullptr, 0);
        std::vector<BYTE> hash(cb);
        if (cb == 0 || !CryptCATAdminCalcHashFromFileHandle2(adm, hf, &cb, hash.data(), 0)) {
            CryptCATAdminReleaseContext(adm, 0);
            continue;
        }

        HCATINFO ci = CryptCATAdminEnumCatalogFromHash(adm, hash.data(), cb, 0, nullptr);
        if (!ci) { CryptCATAdminReleaseContext(adm, 0); continue; }

        CATALOG_INFO info = {};
        info.cbStruct = sizeof(info);
        if (CryptCATCatalogInfoFromContext(ci, &info, 0)) {
            static const wchar_t* hx = L"0123456789ABCDEF";
            std::wstring tag;
            for (DWORD i = 0; i < cb; i++) { tag += hx[hash[i] >> 4]; tag += hx[hash[i] & 15]; }

            WINTRUST_CATALOG_INFO wc = {};
            wc.cbStruct = sizeof(wc);
            wc.pcwszCatalogFilePath = info.wszCatalogFile;
            wc.pcwszMemberTag = tag.c_str();
            wc.pcwszMemberFilePath = path.c_str();
            wc.hMemberFile = hf;
            wc.pbCalculatedFileHash = hash.data();
            wc.cbCalculatedFileHash = cb;
            wc.hCatAdmin = adm;

            WINTRUST_DATA wd;
            InitWintrustData(wd);
            wd.dwUnionChoice = WTD_CHOICE_CATALOG;
            wd.pCatalog = &wc;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG st = WinVerifyTrust(kNoWnd, &action, &wd);
            if (st == 0) publisher = SignerName(wd.hWVTStateData);
            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(kNoWnd, &action, &wd);
            result = st;
        }
        CryptCATAdminReleaseCatalogContext(adm, ci, 0);
        CryptCATAdminReleaseContext(adm, 0);
    }
    CloseHandle(hf);
    return result;
}

// Real path after resolving junctions / symlinks, without the \\?\ prefix.
std::wstring FinalPath(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return path;
    wchar_t buf[2048];
    DWORD n = GetFinalPathNameByHandleW(h, buf, _countof(buf), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(h);
    if (n == 0 || n >= _countof(buf)) return path;
    std::wstring s = buf;
    if (s.rfind(L"\\\\?\\UNC\\", 0) == 0) return L"\\\\" + s.substr(8);
    if (s.rfind(L"\\\\?\\", 0) == 0) return s.substr(4);
    return s;
}

bool InsideWindowsDir(const std::wstring& finalPath)
{
    wchar_t win[MAX_PATH] = {};
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    std::wstring prefix = win;
    if (prefix.back() != L'\\') prefix += L'\\';
    return finalPath.size() > prefix.size() &&
           _wcsnicmp(finalPath.c_str(), prefix.c_str(), prefix.size()) == 0;
}

bool OwnedByTrustedInstaller(const std::wstring& path)
{
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                              &owner, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    bool match = false;
    PSID ti = nullptr;
    // NT SERVICE\TrustedInstaller
    if (ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti)) {
        match = owner && EqualSid(owner, ti) != FALSE;
        LocalFree(ti);
    }
    LocalFree(sd);
    return match;
}

bool StartsWithMicrosoft(const std::wstring& s)
{
    return s.size() >= 9 && _wcsnicmp(s.c_str(), L"Microsoft", 9) == 0;
}

TrustInfo Compute(const std::wstring& path)
{
    TrustInfo t;
    std::wstring pub;

    LONG st = VerifyEmbedded(path, pub);
    if (st == TRUST_E_NOSIGNATURE || st == TRUST_E_PROVIDER_UNKNOWN || st == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        pub.clear();
        LONG cs = VerifyCatalog(path, pub);
        if (cs == 0) { st = 0; t.catalog = true; }
        else if (cs != TRUST_E_NOSIGNATURE) st = cs;       // listed in a catalog but wrong -> tampered
    }
    t.status = st;
    t.publisher = pub;

    if (st == 0) {
        t.cls = TrustClass::SignedValid;
        std::wstring real = FinalPath(path);
        if (StartsWithMicrosoft(pub) && InsideWindowsDir(real) && OwnedByTrustedInstaller(real))
            t.cls = TrustClass::System;
    } else if (st == TRUST_E_NOSIGNATURE || st == TRUST_E_PROVIDER_UNKNOWN || st == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        t.cls = TrustClass::Unsigned;
    } else {
        t.cls = TrustClass::Invalid;
    }
    return t;
}

} // namespace

TrustInfo EvaluateTrust(const std::wstring& pathIn)
{
    wchar_t full[2048];
    DWORD n = GetFullPathNameW(pathIn.c_str(), _countof(full), full, nullptr);
    std::wstring path = (n > 0 && n < _countof(full)) ? std::wstring(full) : pathIn;

    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        TrustInfo t;                                    // Missing
        return t;
    }

    std::wstring key = path + L"|" + std::to_wstring(fad.nFileSizeHigh) + L":" + std::to_wstring(fad.nFileSizeLow) +
                       L"|" + std::to_wstring(fad.ftLastWriteTime.dwHighDateTime) + L":" +
                       std::to_wstring(fad.ftLastWriteTime.dwLowDateTime);
    for (auto& ch : key) ch = static_cast<wchar_t>(towlower(ch));

    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) return it->second;
    }

    TrustInfo t = Compute(path);

    std::lock_guard<std::mutex> lk(g_mu);
    if (g_cache.size() > 512) g_cache.clear();
    g_cache[key] = t;
    return t;
}

} // namespace lg
