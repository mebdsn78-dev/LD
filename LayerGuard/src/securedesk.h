#pragma once
#include <windows.h>
#include <string>

namespace lg {

// Shows a password prompt on a separate, private desktop ("LayerGuardSecure")
// and switches the user's input to it, then switches back. Windows, hooks and
// window messages of the normal desktop cannot reach it; the desktop's DACL
// admits only SYSTEM and Administrators.
//
// `phrase` is the user's personal anti-phishing phrase: a fake prompt cannot
// know it, so the user must refuse to type a password when it is wrong.
//
// Returns true only if the user pressed OK. The password is copied into
// `pwOut` (the caller must SecureZeroMemory it). A timeout closes the prompt.
bool SecurePasswordPrompt(HINSTANCE hInst,
                          const std::wstring& heading,
                          const std::wstring& detail,
                          const std::wstring& phrase,
                          wchar_t* pwOut, size_t pwCch,
                          unsigned timeoutSeconds);

} // namespace lg
