#include "paths.h"
#include <shlobj.h>
#include <sddl.h>
#include <strsafe.h>

BOOL LgDataPath(const wchar_t* file, wchar_t* out, size_t cch)
{
    PWSTR programData = NULL;
    wchar_t dir[MAX_PATH];
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;

    if (FAILED(SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &programData)))
        return FALSE;
    if (FAILED(StringCchPrintfW(dir, MAX_PATH, L"%s\\LayerGuard", programData))) {
        CoTaskMemFree(programData);
        return FALSE;
    }
    CoTaskMemFree(programData);

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    /* Protected DACL: SYSTEM + Administrators only, inherited by every file. */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &psd, NULL))
        sa.lpSecurityDescriptor = psd;

    if (!CreateDirectoryW(dir, &sa) && GetLastError() != ERROR_ALREADY_EXISTS) {
        if (psd) LocalFree(psd);
        return FALSE;
    }
    if (psd) LocalFree(psd);

    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\%s", dir, file));
}
