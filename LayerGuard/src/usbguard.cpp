#include "usbguard.h"
#include "audit.h"
#include "paths.h"
#include <dbt.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <cwctype>

namespace lg {
namespace usbguard {
namespace {

// GUID_DEVINTERFACE_KEYBOARD and GUID_DEVCLASS_KEYBOARD (defined here so the
// project builds with the plain Windows SDK, without the WDK headers).
const GUID kKbdInterface = { 0x884b96c3, 0x56ef, 0x11d1, { 0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd } };
const GUID kKbdClass     = { 0x4d36e96b, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

std::atomic<bool> g_enabled{ true };
HDEVNOTIFY        g_notify = nullptr;
std::mutex        g_mu;                 // protects the sets below and serialises prompts
std::set<std::wstring> g_allow, g_deny;
bool              g_allowFileExisted = false;

struct Kbd {
    std::wstring path;                  // device-interface path (from the notification)
    std::wstring instanceId;            // e.g. HID\VID_046D&PID_C31C\6&2b1d...
    std::wstring desc;
};

std::wstring Lower(std::wstring s)
{
    for (auto& ch : s) ch = static_cast<wchar_t>(towlower(ch));
    return s;
}

// ---- allow / deny lists (one instance ID per line, UTF-8) ------------------------
void LoadList(const wchar_t* file, std::set<std::wstring>& out, bool* existed = nullptr)
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(file, path, MAX_PATH)) return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rt, ccs=UTF-8") != 0 || !f) { if (existed) *existed = false; return; }
    if (existed) *existed = true;
    wchar_t line[512];
    while (fgetws(line, 512, f)) {
        std::wstring s = line;
        while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r')) s.pop_back();
        if (!s.empty()) out.insert(Lower(s));
    }
    fclose(f);
}

void AppendList(const wchar_t* file, const std::wstring& id)
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(file, path, MAX_PATH)) return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"a, ccs=UTF-8") != 0 || !f) return;
    fwprintf(f, L"%s\n", id.c_str());
    fclose(f);
}

// ---- device enumeration --------------------------------------------------------
std::vector<Kbd> EnumKeyboards()
{
    std::vector<Kbd> out;
    HDEVINFO hdi = SetupDiGetClassDevsW(&kKbdInterface, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdi == INVALID_HANDLE_VALUE) return out;

    SP_DEVICE_INTERFACE_DATA ifd = {};
    ifd.cbSize = sizeof(ifd);
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(hdi, nullptr, &kKbdInterface, i, &ifd); ++i) {
        DWORD need = 0;
        SetupDiGetDeviceInterfaceDetailW(hdi, &ifd, nullptr, 0, &need, nullptr);
        if (!need) continue;
        std::vector<BYTE> buf(need);
        auto* det = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buf.data());
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA dd = {};
        dd.cbSize = sizeof(dd);
        if (!SetupDiGetDeviceInterfaceDetailW(hdi, &ifd, det, need, nullptr, &dd)) continue;

        wchar_t id[MAX_DEVICE_ID_LEN] = {};
        if (!SetupDiGetDeviceInstanceIdW(hdi, &dd, id, MAX_DEVICE_ID_LEN, nullptr)) continue;

        wchar_t desc[256] = {};
        SetupDiGetDeviceRegistryPropertyW(hdi, &dd, SPDRP_DEVICEDESC, nullptr,
                                          reinterpret_cast<PBYTE>(desc), sizeof(desc) - sizeof(wchar_t), nullptr);
        out.push_back({ det->DevicePath, Lower(id), desc });
    }
    SetupDiDestroyDeviceInfoList(hdi);
    return out;
}

// Enable or disable a device node of class "Keyboard" by instance ID.
bool SetDeviceEnabled(const std::wstring& instanceId, bool enable)
{
    HDEVINFO hdi = SetupDiGetClassDevsW(&kKbdClass, nullptr, nullptr, DIGCF_PRESENT);
    if (hdi == INVALID_HANDLE_VALUE) return false;
    bool done = false;
    SP_DEVINFO_DATA dd = {};
    dd.cbSize = sizeof(dd);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hdi, i, &dd); ++i) {
        wchar_t id[MAX_DEVICE_ID_LEN] = {};
        if (!SetupDiGetDeviceInstanceIdW(hdi, &dd, id, MAX_DEVICE_ID_LEN, nullptr)) continue;
        if (_wcsicmp(id, instanceId.c_str()) != 0) continue;

        SP_PROPCHANGE_PARAMS p = {};
        p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        p.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
        p.Scope = DICS_FLAG_GLOBAL;
        p.HwProfile = 0;
        done = SetupDiSetClassInstallParamsW(hdi, &dd, &p.ClassInstallHeader, sizeof(p)) &&
               SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hdi, &dd);
        break;
    }
    SetupDiDestroyDeviceInfoList(hdi);
    return done;
}

// ---- the decision flow -----------------------------------------------------------
//   unknown keyboard appears -> disable it at once -> ask the user
//   "Yes, it is a keyboard I plugged in" -> allow-list it, re-enable it
//   "No" (or closing the box)            -> stays disabled, remembered as blocked
void HandleNewKeyboard(Kbd k)
{
    std::lock_guard<std::mutex> lk(g_mu);          // one prompt at a time
    if (!g_enabled) return;
    if (g_allow.count(k.instanceId)) return;

    if (g_deny.count(k.instanceId)) {
        SetDeviceEnabled(k.instanceId, false);
        LgAuditWrite(L"USB blocked-again keyboard id=%s", k.instanceId.c_str());
        return;
    }

    bool quarantined = SetDeviceEnabled(k.instanceId, false);   // BEFORE asking
    LgAuditWrite(L"USB new keyboard quarantined=%d id=%s desc=%s",
                 quarantined ? 1 : 0, k.instanceId.c_str(), k.desc.c_str());

    std::wstring text =
        L"تم توصيل جهاز إدخال جديد يعرّف نفسه ككيبورد، وقد عُطّل مؤقتاً.\n"
        L"A new device identifying itself as a KEYBOARD was plugged in and has been disabled.\n\n"
        L"Device: " + k.desc + L"\nID: " + k.instanceId +
        L"\n\nهل هذا كيبورد حقيقي وأنت من قام بتوصيله؟\n"
        L"Is this really a keyboard that you plugged in?\n\n"
        L"نعم (Yes) = تفعيله كلوحة مفاتيح عادية\n"
        L"لا (No) = إبقاؤه معطّلاً (الافتراضي)";

    // "No" is the default button, so a stray Enter from the device itself
    // can never approve it.
    int r = MessageBoxW(nullptr, text.c_str(), L"LayerGuard — USB Guard",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_TOPMOST | MB_SETFOREGROUND);
    if (r == IDYES) {
        g_allow.insert(k.instanceId);
        AppendList(L"usb_allow.txt", k.instanceId);       // persist first, then enable
        bool en = SetDeviceEnabled(k.instanceId, true);
        LgAuditWrite(L"USB keyboard APPROVED enabled=%d id=%s", en ? 1 : 0, k.instanceId.c_str());
    } else {
        g_deny.insert(k.instanceId);
        AppendList(L"usb_deny.txt", k.instanceId);
        LgAuditWrite(L"USB keyboard REJECTED (stays disabled) id=%s", k.instanceId.c_str());
    }
}

void HandleArrivalPath(std::wstring path)
{
    for (int attempt = 0; attempt < 5; ++attempt) {
        for (const Kbd& k : EnumKeyboards()) {
            if (_wcsicmp(k.path.c_str(), path.c_str()) == 0) { HandleNewKeyboard(k); return; }
        }
        Sleep(200);                                       // interface not listed yet
    }
}

} // namespace

bool Init(HWND hwnd)
{
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_allow.clear();
        g_deny.clear();
        LoadList(L"usb_allow.txt", g_allow, &g_allowFileExisted);
        LoadList(L"usb_deny.txt", g_deny);
    }

    std::vector<Kbd> present = EnumKeyboards();
    if (!g_allowFileExisted) {
        // First run: whatever is plugged in right now is the trusted baseline.
        std::lock_guard<std::mutex> lk(g_mu);
        for (const Kbd& k : present) {
            g_allow.insert(k.instanceId);
            AppendList(L"usb_allow.txt", k.instanceId);
            LgAuditWrite(L"USB baseline keyboard trusted id=%s", k.instanceId.c_str());
        }
        if (present.empty()) AppendList(L"usb_allow.txt", L"");   // create the file anyway
    } else {
        for (const Kbd& k : present) {
            bool known;
            { std::lock_guard<std::mutex> lk(g_mu); known = g_allow.count(k.instanceId) != 0; }
            if (!known) std::thread(HandleNewKeyboard, k).detach();
        }
    }

    DEV_BROADCAST_DEVICEINTERFACE_W filter = {};
    filter.dbcc_size = sizeof(filter);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = kKbdInterface;
    g_notify = RegisterDeviceNotificationW(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
    LgAuditWrite(L"USB guard started registered=%d baseline_keyboards=%zu", g_notify ? 1 : 0, present.size());
    return g_notify != nullptr;
}

void Shutdown()
{
    if (g_notify) { UnregisterDeviceNotification(g_notify); g_notify = nullptr; }
}

void OnDeviceChange(WPARAM wParam, LPARAM lParam)
{
    if (!g_enabled || wParam != DBT_DEVICEARRIVAL || !lParam) return;
    auto* hdr = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
    if (hdr->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE) return;
    auto* di = reinterpret_cast<DEV_BROADCAST_DEVICEINTERFACE_W*>(lParam);
    if (!IsEqualGUID(di->dbcc_classguid, kKbdInterface)) return;

    std::thread(HandleArrivalPath, std::wstring(di->dbcc_name)).detach();   // never block the UI thread
}

void SetEnabled(bool enabled)
{
    g_enabled = enabled;
    LgAuditWrite(L"USB guard %s", enabled ? L"ENABLED" : L"DISABLED");
}

bool IsEnabled() { return g_enabled; }

} // namespace usbguard
} // namespace lg
