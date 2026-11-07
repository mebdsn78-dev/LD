#include "securedesk.h"
#include "audit.h"
#include <sddl.h>

namespace lg {
namespace {

constexpr wchar_t kClass[] = L"LayerGuardSecurePrompt";
enum { ID_EDIT = 1001, ID_NOTE = 1002 };

struct Ctx {
    HINSTANCE    hInst = nullptr;
    HDESK        desk = nullptr;
    std::wstring heading, detail, phrase;
    wchar_t*     out = nullptr;
    size_t       cch = 0;
    bool         ok = false;
    bool         failed = false;
    HANDLE       ready = nullptr;
    HWND         edit = nullptr;
    HFONT        fontBig = nullptr, fontNormal = nullptr, fontPhrase = nullptr;
};

HFONT MakeFont(int height, int weight)
{
    return CreateFontW(-height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

HWND AddChild(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, DWORD ex,
              int x, int y, int w, int h, int id, HFONT font, HINSTANCE inst)
{
    HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h,
                             parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), inst, nullptr);
    if (c && font) SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return c;
}

LRESULT CALLBACK PromptProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    Ctx* c = reinterpret_cast<Ctx*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    switch (m) {
    case WM_NCCREATE:
        SetWindowLongPtrW(h, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams));
        return DefWindowProcW(h, m, w, l);

    case WM_CREATE: {
        c = reinterpret_cast<Ctx*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
        AddChild(h, L"STATIC", c->heading.c_str(), 0, 0, 20, 14, 480, 28, -1, c->fontBig, c->hInst);
        AddChild(h, L"STATIC", c->detail.c_str(), 0, 0, 20, 48, 480, 44, -1, c->fontNormal, c->hInst);
        AddChild(h, L"STATIC", L"عبارة التحقق الخاصة بك (Your security phrase):", 0, 0,
                 20, 98, 480, 20, -1, c->fontNormal, c->hInst);
        AddChild(h, L"STATIC", c->phrase.c_str(), SS_CENTER | WS_BORDER, 0,
                 20, 120, 480, 32, -1, c->fontPhrase, c->hInst);
        AddChild(h, L"STATIC", L"إن لم تطابق العبارة عبارتك فأغلق النافذة ولا تُدخل كلمة المرور.", 0, 0,
                 20, 158, 480, 20, ID_NOTE, c->fontNormal, c->hInst);
        c->edit = AddChild(h, L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                           0, 20, 186, 480, 28, ID_EDIT, c->fontNormal, c->hInst);
        AddChild(h, L"BUTTON", L"موافق (OK)", WS_TABSTOP | BS_DEFPUSHBUTTON, 0,
                 290, 234, 100, 32, IDOK, c->fontNormal, c->hInst);
        AddChild(h, L"BUTTON", L"إلغاء (Cancel)", WS_TABSTOP | BS_PUSHBUTTON, 0,
                 400, 234, 100, 32, IDCANCEL, c->fontNormal, c->hInst);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDOK && c) {
            GetWindowTextW(c->edit, c->out, static_cast<int>(c->cch));
            // Best-effort wipe of the edit control's own copy.
            SetWindowTextW(c->edit, L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            SetWindowTextW(c->edit, L"");
            c->ok = true;
            DestroyWindow(h);
        } else if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(h);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

DWORD WINAPI PromptThread(LPVOID p)
{
    Ctx* c = static_cast<Ctx*>(p);
    // Must be done before this thread owns any window or hook.
    if (!SetThreadDesktop(c->desk)) {
        c->failed = true;
        SetEvent(c->ready);
        return 1;
    }
    const int W = 520, H = 290;
    int x = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;
    HWND h = CreateWindowExW(WS_EX_TOPMOST, kClass, L"LayerGuard", WS_POPUP | WS_BORDER | WS_VISIBLE,
                             x, y, W, H, nullptr, nullptr, c->hInst, c);
    if (!h) {
        c->failed = true;
        SetEvent(c->ready);
        return 1;
    }
    SetForegroundWindow(h);
    SetFocus(c->edit);
    SetEvent(c->ready);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(h, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return 0;
}

} // namespace

bool SecurePasswordPrompt(HINSTANCE hInst, const std::wstring& heading, const std::wstring& detail,
                          const std::wstring& phrase, wchar_t* pwOut, size_t pwCch, unsigned timeoutSeconds)
{
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = PromptProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = kClass;
        RegisterClassExW(&wc);
        registered = true;
    }
    if (!pwOut || pwCch < 2) return false;
    pwOut[0] = 0;

    Ctx c;
    c.hInst = hInst;
    c.heading = heading;
    c.detail = detail;
    c.phrase = phrase;
    c.out = pwOut;
    c.cch = pwCch;
    c.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    c.fontBig = MakeFont(20, FW_BOLD);
    c.fontNormal = MakeFont(15, FW_NORMAL);
    c.fontPhrase = MakeFont(18, FW_BOLD);

    HDESK orig = GetThreadDesktop(GetCurrentThreadId());
    HDESK input = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);

    // Only SYSTEM and Administrators may open the desktop.
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &psd, nullptr))
        sa.lpSecurityDescriptor = psd;

    HDESK sec = CreateDesktopW(L"LayerGuardSecure", nullptr, nullptr, 0, GENERIC_ALL, &sa);
    if (psd) LocalFree(psd);

    bool result = false;
    if (sec) {
        c.desk = sec;
        DWORD tid = 0;
        HANDLE th = CreateThread(nullptr, 0, PromptThread, &c, 0, &tid);
        if (th) {
            WaitForSingleObject(c.ready, 5000);
            bool switched = !c.failed && SwitchDesktop(sec);
            if (switched) {
                LgAuditWrite(L"SECURE_DESKTOP entered");
                if (WaitForSingleObject(th, timeoutSeconds * 1000) == WAIT_TIMEOUT) {
                    PostThreadMessageW(tid, WM_QUIT, 0, 0);
                    if (WaitForSingleObject(th, 3000) == WAIT_TIMEOUT) TerminateThread(th, 1);
                    LgAuditWrite(L"SECURE_DESKTOP prompt timed out");
                }
            } else {
                PostThreadMessageW(tid, WM_QUIT, 0, 0);
                WaitForSingleObject(th, 3000);
            }
            // Always return the user to the normal desktop.
            SwitchDesktop(input ? input : orig);
            LgAuditWrite(L"SECURE_DESKTOP left");
            CloseHandle(th);
            result = switched && c.ok;
        }
        CloseDesktop(sec);
    }
    if (input) CloseDesktop(input);

    DeleteObject(c.fontBig);
    DeleteObject(c.fontNormal);
    DeleteObject(c.fontPhrase);
    CloseHandle(c.ready);
    return result;
}

} // namespace lg
