// LayerGuard — layered sandbox manager (Win32 GUI).
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dbt.h>
#include <ctime>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "audit.h"
#include "layermgr.h"
#include "layers.h"
#include "paths.h"
#include "procfreeze.h"
#include "procmon.h"
#include "sandbox.h"
#include "usbguard.h"

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

enum {
    IDC_LIST = 100, IDC_ADD, IDC_VERIFY, IDC_USB, IDC_LOG, IDC_MON, IDC_ALERT,
    IDM_LAUNCH = 200, IDM_REMOVE, IDM_MON_RERUN, IDM_MON_KILL,
    IDM_LAYER_BASE = 300                       // 300..315
};
constexpr UINT_PTR kTimerId = 1;
constexpr UINT WM_APP_PROC = WM_APP + 1;   // posted by the real-time process monitor
constexpr WORD  kIconId = 1;               // resources.rc: 1 ICON "layerguard.ico"

HINSTANCE        g_hInst = nullptr;
HWND             g_hwnd = nullptr, g_list = nullptr, g_log = nullptr, g_usb = nullptr;
HWND             g_mon = nullptr, g_alert = nullptr;
HFONT            g_font = nullptr;
lg::ProcMonitor  g_procMon;
std::map<LPARAM, lg::ProcEvent> g_evMap;   // monitor rows -> event data
bool             g_alertOpen = false;
lg::LayerManager g_mgr;
std::wstring     g_lastLog;

LONG WINAPI CrashFilter(EXCEPTION_POINTERS*)
{
    lg::ThawAll();                             // never leave the desktop frozen after a crash
    return EXCEPTION_CONTINUE_SEARCH;
}

std::wstring FromUtf8(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ---- audit view: last entries of the log, human readable ---------------------------
std::wstring BuildLogText()
{
    wchar_t path[MAX_PATH];
    if (!LgDataPath(L"audit.log", path, MAX_PATH)) return L"";
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    LARGE_INTEGER size = {};
    GetFileSizeEx(h, &size);
    const LONGLONG window = 12 * 1024;
    LONGLONG start = size.QuadPart > window ? size.QuadPart - window : 0;
    LARGE_INTEGER pos;
    pos.QuadPart = start;
    SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    std::string buf((size_t)(size.QuadPart - start), '\0');
    DWORD got = 0;
    if (!buf.empty()) ReadFile(h, &buf[0], (DWORD)buf.size(), &got, nullptr);
    CloseHandle(h);
    buf.resize(got);

    std::wstring out;
    size_t p = 0;
    if (start > 0) { size_t nl = buf.find('\n'); p = (nl == std::string::npos) ? buf.size() : nl + 1; }
    while (p < buf.size()) {
        size_t e = buf.find('\n', p);
        if (e == std::string::npos) e = buf.size();
        std::string line = buf.substr(p, e - p);
        p = e + 1;
        // fields: seq, time, message, prev, hash
        std::vector<std::string> f;
        size_t s = 0;
        for (int i = 0; i < 4; i++) {
            size_t t = line.find('\t', s);
            if (t == std::string::npos) break;
            f.push_back(line.substr(s, t - s));
            s = t + 1;
        }
        if (f.size() < 3) continue;
        time_t tt = (time_t)_atoi64(f[1].c_str());
        tm lt = {};
        localtime_s(&lt, &tt);
        wchar_t ts[32];
        wcsftime(ts, 32, L"%H:%M:%S", &lt);
        out += L"#" + FromUtf8(f[0]) + L"  " + ts + L"  " + FromUtf8(f[2]) + L"\r\n";
    }
    return out;
}

void RefreshLog()
{
    std::wstring t = BuildLogText();
    if (t == g_lastLog) return;
    g_lastLog = t;
    SetWindowTextW(g_log, t.c_str());
    int len = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
}

// ---- list ------------------------------------------------------------------------------
std::wstring LayerText(int id)
{
    const LgLayer* L = LgGetLayer(id);
    return std::to_wstring(id) + L" — " + (L ? L->name : L"?");
}

void RefreshList()
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    ListView_DeleteAllItems(g_list);
    auto& apps = g_mgr.Apps();
    for (int i = 0; i < (int)apps.size(); i++) {
        const lg::AppEntry& a = apps[i];
        LVITEMW it = {};
        it.mask = LVIF_TEXT;
        it.iItem = i;
        it.pszText = const_cast<LPWSTR>(a.display.c_str());
        ListView_InsertItem(g_list, &it);
        std::wstring layer = LayerText(a.layer);
        std::wstring status = a.Running() ? (L"Running (PID " + std::to_wstring(a.pid) + L")") : L"Stopped";
        std::wstring trust = a.trust.Text();
        ListView_SetItemText(g_list, i, 1, const_cast<LPWSTR>(layer.c_str()));
        ListView_SetItemText(g_list, i, 2, const_cast<LPWSTR>(trust.c_str()));
        ListView_SetItemText(g_list, i, 3, const_cast<LPWSTR>(status.c_str()));
        ListView_SetItemText(g_list, i, 4, const_cast<LPWSTR>(a.path.c_str()));
    }
    if (sel >= 0 && sel < (int)apps.size())
        ListView_SetItemState(g_list, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
}

int SelectedIndex() { return ListView_GetNextItem(g_list, -1, LVNI_SELECTED); }

// ---- actions -----------------------------------------------------------------------------
void DoLaunchOrStop(int idx)
{
    auto& apps = g_mgr.Apps();
    if (idx < 0 || idx >= (int)apps.size()) return;
    if (apps[idx].Running()) {
        g_mgr.Stop(idx);
    } else {
        std::wstring err;
        if (!g_mgr.Launch(idx, err))
            MessageBoxW(g_hwnd, err.c_str(), L"LayerGuard — launch failed", MB_ICONERROR);
    }
    RefreshList();
    RefreshLog();
}

void DoChangeLayer(int idx, int newLayer)
{
    auto& apps = g_mgr.Apps();
    if (idx < 0 || idx >= (int)apps.size()) return;
    std::wstring msg;
    lg::ChangeResult r = g_mgr.ChangeLayer((size_t)idx, newLayer, msg);

    UINT icon = (r == lg::ChangeResult::Granted) ? MB_ICONINFORMATION : MB_ICONWARNING;
    if (r != lg::ChangeResult::Cancelled)
        MessageBoxW(g_hwnd, msg.c_str(), L"LayerGuard", MB_OK | icon);

    if (r == lg::ChangeResult::Granted && apps[idx].Running()) {
        // A running process keeps the limits it was created with, so the new
        // layer is applied by re-creating the process inside it.
        if (MessageBoxW(g_hwnd,
                        L"التطبيق قيد التشغيل. يجب إعادة تشغيله ليُطبَّق الطبقة الجديدة. إغلاقه وتشغيله الآن؟\n"
                        L"The app is running; restart it now so the new layer takes effect? (unsaved work will be lost)",
                        L"LayerGuard", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
            g_mgr.Stop(idx);
            std::wstring err;
            if (!g_mgr.Launch(idx, err))
                MessageBoxW(g_hwnd, err.c_str(), L"LayerGuard — launch failed", MB_ICONERROR);
        }
    }
    RefreshList();
    RefreshLog();
}

void ShowContextMenu(int idx)
{
    auto& apps = g_mgr.Apps();
    if (idx < 0 || idx >= (int)apps.size()) return;
    const lg::AppEntry& a = apps[idx];

    HMENU menu = CreatePopupMenu();
    HMENU sub = CreatePopupMenu();
    for (int n = 0; n < LG_LAYER_COUNT; n++) {
        UINT fl = MF_STRING;
        if (n == a.layer) fl |= MF_CHECKED | MF_GRAYED;
        if (n == LG_LAYER_KERNEL) fl |= MF_GRAYED;                 // reserved
        AppendMenuW(sub, fl, IDM_LAYER_BASE + n, LayerText(n).c_str());
    }
    AppendMenuW(menu, MF_STRING, IDM_LAUNCH, a.Running() ? L"إيقاف (Stop)" : L"تشغيل (Launch)");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)sub, L"تعديل الطبقة (Change Layer)");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_REMOVE, L"إزالة من القائمة (Remove)");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(menu);                                              // also destroys the submenu
    PostMessageW(g_hwnd, WM_NULL, 0, 0);

    if (cmd == IDM_LAUNCH) DoLaunchOrStop(idx);
    else if (cmd == IDM_REMOVE) { g_mgr.RemoveApp((size_t)idx); RefreshList(); RefreshLog(); }
    else if (cmd >= IDM_LAYER_BASE && cmd < IDM_LAYER_BASE + LG_LAYER_COUNT)
        DoChangeLayer(idx, cmd - IDM_LAYER_BASE);
}

void DoAddApp()
{
    wchar_t file[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Applications (*.exe)\0*.exe\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;
    std::wstring summary;
    if (!g_mgr.AddApp(file, &summary))
        MessageBoxW(g_hwnd, L"This application is already in the list.", L"LayerGuard", MB_ICONINFORMATION);
    else
        MessageBoxW(g_hwnd, summary.c_str(), L"LayerGuard — تقييم التطبيق", MB_OK | MB_ICONINFORMATION);
    RefreshList();
    RefreshLog();
}

void DoVerifyAudit()
{
    long long bad = 0, total = 0;
    bool ok = LgAuditVerify(&bad, &total) != FALSE;
    wchar_t m[256];
    if (ok) swprintf_s(m, L"سجل التدقيق سليم.\nAudit chain intact: %lld entries verified.", total);
    else    swprintf_s(m, L"تحذير: السلسلة مكسورة عند السطر %lld!\nWARNING: audit chain broken at line %lld (of %lld).", bad, bad, total);
    MessageBoxW(g_hwnd, m, L"LayerGuard — Audit", ok ? MB_ICONINFORMATION : MB_ICONERROR);
    LgAuditWrite(L"AUDIT verify result=%s entries=%lld", ok ? L"intact" : L"BROKEN", total);
}

void OnUsbToggle()
{
    bool wantOn = SendMessageW(g_usb, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (wantOn) { lg::usbguard::SetEnabled(true); return; }

    // Switching a security control OFF requires the same authentication as raising a layer.
    std::wstring msg;
    auto r = g_mgr.Authenticate(L"إيقاف حارس USB (Disable USB Guard).", msg,
                                [] { lg::usbguard::SetEnabled(false); });
    if (r != lg::AuthResult::Ok) {
        SendMessageW(g_usb, BM_SETCHECK, BST_CHECKED, 0);
        if (r != lg::AuthResult::Cancelled) MessageBoxW(g_hwnd, msg.c_str(), L"LayerGuard", MB_ICONWARNING);
    }
    RefreshLog();
}

// ---- real-time process monitor ------------------------------------------------------------
void AddMonColumn(int i, const wchar_t* t, int w)
{
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH;
    c.pszText = const_cast<LPWSTR>(t);
    c.cx = w;
    ListView_InsertColumn(g_mon, i, &c);
}

// Starts the program inside layer 0 FIRST, and only if that worked ends the original
// process, so a failed sandbox launch never costs the user a running program.
bool RerunInLayer0(const lg::ProcEvent& ev)
{
    lg::LaunchResult r = lg::LaunchInLayer(ev.path, 0);
    if (!r.ok) {
        std::wstring m = L"تعذّر تشغيله في الطبقة 0؛ تُرك البرنامج الأصلي كما هو.\n"
                         L"Could not start it in layer 0; the original process was left running.\n\n" + r.error;
        MessageBoxW(g_hwnd, m.c_str(), L"LayerGuard", MB_ICONWARNING);
        LgAuditWrite(L"MONITOR sandbox re-run FAILED pid=%lu path=%s: %s", ev.pid, ev.path.c_str(), r.error.c_str());
        return false;
    }
    CloseHandle(r.hProcess);
    bool killed = lg::TerminateIfSame(ev);
    LgAuditWrite(L"MONITOR re-run in layer 0 pid=%lu original_terminated=%d path=%s",
                 ev.pid, killed ? 1 : 0, ev.path.c_str());
    return true;
}

void OfferSandbox(const lg::ProcEvent& ev)
{
    if (g_alertOpen) return;                       // never stack dialogs; the row is still listed
    g_alertOpen = true;
    std::wstring t = L"بدأ برنامج " + std::wstring(ev.trust.cls == lg::TrustClass::Invalid ? L"بتوقيع غير صالح" : L"غير موقّع") +
                     L":\n" + ev.name + L"  (PID " + std::to_wstring(ev.pid) + L")\n" + ev.path +
                     L"\n\nهل تريد إيقافه وتشغيله داخل الطبقة 0 (الصندوق المعزول)؟\n"
                     L"An " + (ev.trust.cls == lg::TrustClass::Invalid ? L"invalid-signature" : L"unsigned") +
                     L" program just started. Re-run it inside layer 0 (sandbox)?\n\n"
                     L"(سيفقد البرنامج وسائط التشغيل والعمل غير المحفوظ / command-line arguments and unsaved work are lost)";
    int r = MessageBoxW(g_hwnd, t.c_str(), L"LayerGuard — Live monitor",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST);
    if (r == IDYES) RerunInLayer0(ev);
    g_alertOpen = false;
}

void OnProcEvent(lg::ProcEvent* raw)
{
    std::unique_ptr<lg::ProcEvent> ev(raw);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t ts[16];
    swprintf_s(ts, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);

    std::wstring verdict = ev->sandboxed ? std::wstring(L"داخل صندوق LayerGuard 🛡") : ev->trust.Text();
    std::wstring pid = std::to_wstring(ev->pid);

    LVITEMW it = {};
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = 0;
    it.pszText = ts;
    it.lParam = static_cast<LPARAM>(ev->id);
    int row = ListView_InsertItem(g_mon, &it);
    ListView_SetItemText(g_mon, row, 1, const_cast<LPWSTR>(ev->name.c_str()));
    ListView_SetItemText(g_mon, row, 2, const_cast<LPWSTR>(verdict.c_str()));
    ListView_SetItemText(g_mon, row, 3, const_cast<LPWSTR>(pid.c_str()));
    ListView_SetItemText(g_mon, row, 4, const_cast<LPWSTR>(ev->path.c_str()));
    g_evMap[static_cast<LPARAM>(ev->id)] = *ev;

    while (ListView_GetItemCount(g_mon) > 300) {           // keep the view bounded
        int last = ListView_GetItemCount(g_mon) - 1;
        LVITEMW q = {};
        q.mask = LVIF_PARAM;
        q.iItem = last;
        if (ListView_GetItem(g_mon, &q)) g_evMap.erase(q.lParam);
        ListView_DeleteItem(g_mon, last);
    }

    bool risky = !ev->sandboxed &&
                 (ev->trust.cls == lg::TrustClass::Unsigned || ev->trust.cls == lg::TrustClass::Invalid);
    if (risky) {                                           // only the interesting ones go to the audit log
        LgAuditWrite(L"MONITOR new process pid=%lu ppid=%lu name=%s verdict=%s path=%s status=0x%08lX",
                     ev->pid, ev->ppid, ev->name.c_str(), ev->trust.Text().c_str(), ev->path.c_str(),
                     (unsigned long)ev->trust.status);
        if (SendMessageW(g_alert, BM_GETCHECK, 0, 0) == BST_CHECKED) OfferSandbox(*ev);
    }
}

void ShowMonMenu(int item)
{
    LVITEMW it = {};
    it.mask = LVIF_PARAM;
    it.iItem = item;
    if (!ListView_GetItem(g_mon, &it)) return;
    auto f = g_evMap.find(it.lParam);
    if (f == g_evMap.end()) return;
    lg::ProcEvent ev = f->second;                          // copy: the map may change while the menu is open

    HMENU menu = CreatePopupMenu();
    UINT fl = ev.sandboxed ? MF_GRAYED : 0;
    AppendMenuW(menu, MF_STRING | fl, IDM_MON_RERUN, L"إعادة تشغيله في الطبقة 0 (Re-run in Layer 0)");
    AppendMenuW(menu, MF_STRING | fl, IDM_MON_KILL, L"إنهاء العملية (Terminate)");
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(menu);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);

    if (cmd == IDM_MON_RERUN) RerunInLayer0(ev);
    else if (cmd == IDM_MON_KILL) {
        bool ok = lg::TerminateIfSame(ev);
        LgAuditWrite(L"MONITOR terminate pid=%lu ok=%d path=%s", ev.pid, ok ? 1 : 0, ev.path.c_str());
        if (!ok) MessageBoxW(g_hwnd, L"تعذّر إنهاء العملية (انتهت أو محمية).\nCould not terminate it (already gone or protected).",
                             L"LayerGuard", MB_ICONINFORMATION);
    }
    RefreshLog();
}

void Layout(int w, int h)
{
    const int m = 8, top = 8, bar = 28, botH = 190;
    MoveWindow(GetDlgItem(g_hwnd, IDC_ADD), m, top, 190, bar, TRUE);
    MoveWindow(GetDlgItem(g_hwnd, IDC_VERIFY), m + 198, top, 210, bar, TRUE);
    MoveWindow(g_usb, m + 420, top + 4, 170, 22, TRUE);
    MoveWindow(g_alert, m + 600, top + 4, w - (m + 600) - m, 22, TRUE);
    MoveWindow(g_list, m, top + bar + 8, w - 2 * m, h - (top + bar + 8) - botH - 2 * m, TRUE);
    int monW = (w - 3 * m) * 62 / 100;
    MoveWindow(g_mon, m, h - botH - m, monW, botH, TRUE);
    MoveWindow(g_log, 2 * m + monW, h - botH - m, w - 3 * m - monW, botH, TRUE);
}

HWND MakeCtl(const wchar_t* cls, const wchar_t* text, DWORD style, DWORD ex, int id)
{
    HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                             g_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_hInst, nullptr);
    SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    return c;
}

void AddColumn(int i, const wchar_t* t, int w)
{
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH;
    c.pszText = const_cast<LPWSTR>(t);
    c.cx = w;
    ListView_InsertColumn(g_list, i, &c);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        g_hwnd = h;
        NONCLIENTMETRICSW ncm = { sizeof(ncm) };
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        g_font = CreateFontIndirectW(&ncm.lfMessageFont);

        MakeCtl(L"BUTTON", L"إضافة تطبيق (Add App)…", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_ADD);
        MakeCtl(L"BUTTON", L"فحص سجل التدقيق (Verify Audit)", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_VERIFY);
        g_usb = MakeCtl(L"BUTTON", L"حارس USB (USB Guard)", BS_AUTOCHECKBOX | WS_TABSTOP, 0, IDC_USB);
        SendMessageW(g_usb, BM_SETCHECK, BST_CHECKED, 0);
        g_alert = MakeCtl(L"BUTTON", L"تنبيه عند تشغيل برنامج غير موقّع (Live alert)", BS_AUTOCHECKBOX | WS_TABSTOP, 0, IDC_ALERT);
        SendMessageW(g_alert, BM_SETCHECK, BST_CHECKED, 0);

        g_list = MakeCtl(WC_LISTVIEWW, L"", LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
                         WS_EX_CLIENTEDGE, IDC_LIST);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        AddColumn(0, L"Application", 160);
        AddColumn(1, L"Layer", 210);
        AddColumn(2, L"Signature / التوقيع", 210);
        AddColumn(3, L"Status", 120);
        AddColumn(4, L"Path", 380);

        g_mon = MakeCtl(WC_LISTVIEWW, L"", LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
                        WS_EX_CLIENTEDGE, IDC_MON);
        ListView_SetExtendedListViewStyle(g_mon, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        AddMonColumn(0, L"Time", 62);
        AddMonColumn(1, L"Live process", 120);
        AddMonColumn(2, L"Signature / التوقيع", 190);
        AddMonColumn(3, L"PID", 52);
        AddMonColumn(4, L"Path", 300);

        g_log = MakeCtl(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                        WS_EX_CLIENTEDGE, IDC_LOG);

        RefreshList();
        RefreshLog();
        SetTimer(h, kTimerId, 1000, nullptr);
        return 0;
    }
    case WM_SIZE:
        if (w != SIZE_MINIMIZED) Layout(LOWORD(l), HIWORD(l));
        return 0;

    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_ADD:    DoAddApp(); break;
        case IDC_VERIFY: DoVerifyAudit(); RefreshLog(); break;
        case IDC_USB:    OnUsbToggle(); break;
        }
        return 0;

    case WM_NOTIFY: {
        auto* nh = reinterpret_cast<NMHDR*>(l);
        if (nh->idFrom == IDC_MON && nh->code == NM_RCLICK) {
            auto* ia = reinterpret_cast<NMITEMACTIVATE*>(l);
            if (ia->iItem >= 0) {
                ListView_SetItemState(g_mon, ia->iItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                ShowMonMenu(ia->iItem);
            }
        }
        if (nh->idFrom == IDC_LIST) {
            auto* ia = reinterpret_cast<NMITEMACTIVATE*>(l);
            if (nh->code == NM_RCLICK && ia->iItem >= 0) {
                ListView_SetItemState(g_list, ia->iItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                ShowContextMenu(ia->iItem);
            } else if (nh->code == NM_DBLCLK && ia->iItem >= 0) {
                DoLaunchOrStop(ia->iItem);
            }
        }
        return 0;
    }
    case WM_TIMER:
        {
            static int ticks = 0;
            bool dirty = g_mgr.RefreshProcessState();
            if (++ticks % 10 == 0 && g_mgr.RescanTrust()) dirty = true;   // live signature re-check every 10 s
            if (dirty) RefreshList();
        }
        RefreshLog();
        return 0;

    case WM_APP_PROC:
        OnProcEvent(reinterpret_cast<lg::ProcEvent*>(l));
        return 0;

    case WM_DEVICECHANGE:
        lg::usbguard::OnDeviceChange(w, l);
        return TRUE;

    case WM_DESTROY:
        KillTimer(h, kTimerId);
        g_procMon.Stop();
        lg::usbguard::Shutdown();
        lg::ThawAll();
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow)
{
    g_hInst = hInst;

    HANDLE single = CreateMutexW(nullptr, TRUE, L"Local\\LayerGuard.Single");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"LayerGuard is already running.", L"LayerGuard", MB_ICONINFORMATION);
        return 0;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    SetUnhandledExceptionFilter(CrashFilter);

    if (!LgAuditInit()) {
        MessageBoxW(nullptr, L"Cannot open the audit log in %ProgramData%\\LayerGuard.\nRun LayerGuard as Administrator.",
                    L"LayerGuard", MB_ICONERROR);
        return 1;
    }
    LgAuditWrite(L"START LayerGuard");
    g_mgr.Init(hInst);

    if (!g_mgr.HasPassword()) {
        MessageBoxW(nullptr,
                    L"مرحباً! لم يتم إعداد كلمة مرور بعد.\nسيُفتح سطح مكتب آمن لإنشاء كلمة المرور وعبارة التحقق الخاصة بك.\n\n"
                    L"Welcome! No password is set. A secure desktop will open so you can create your password.",
                    L"LayerGuard — first run", MB_OK | MB_ICONINFORMATION);
        std::wstring phrase, err;
        if (!g_mgr.FirstRunSetup(phrase, err)) {
            MessageBoxW(nullptr, err.c_str(), L"LayerGuard — setup failed", MB_ICONERROR);
            return 1;
        }
        std::wstring m = L"عبارة التحقق الخاصة بك (احفظها):\nYour security phrase (remember it):\n\n    " + phrase +
                         L"\n\nستظهر في كل نافذة طلب كلمة المرور. إن ظهرت عبارة مختلفة فلا تُدخل كلمة المرور.\n"
                         L"It appears in every password prompt. If it is ever different, do NOT type your password.";
        MessageBoxW(nullptr, m.c_str(), L"LayerGuard", MB_OK | MB_ICONINFORMATION);
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"LayerGuardMain";
    wc.hIcon = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(kIconId), IMAGE_ICON,
                                              GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR));
    wc.hIconSm = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(kIconId), IMAGE_ICON,
                                                GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
    if (!wc.hIcon) wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"LayerGuard — 16-Layer Sandbox Manager",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1120, 720,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    lg::usbguard::Init(hwnd);
    g_procMon.Start(hwnd, WM_APP_PROC);          // real-time process monitor
    LgAuditWrite(L"MONITOR real-time process monitor started");
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    LgAuditWrite(L"STOP LayerGuard");
    CloseHandle(single);
    return (int)msg.wParam;
}
