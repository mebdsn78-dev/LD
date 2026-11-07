#pragma once
#include <windows.h>

namespace lg {
namespace usbguard {

// Registers for keyboard-interface arrival notifications on `hwnd`.
// On first run every keyboard that is currently present becomes trusted.
// On later runs any present keyboard that is not on the allow list is
// quarantined and the user is asked.
bool Init(HWND hwnd);
void Shutdown();

// Call from the window procedure for WM_DEVICECHANGE.
void OnDeviceChange(WPARAM wParam, LPARAM lParam);

void SetEnabled(bool enabled);
bool IsEnabled();

} // namespace usbguard
} // namespace lg
