#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Builds %ProgramData%\LayerGuard\<file>. The directory is created on first
   use with a DACL that gives SYSTEM and Administrators full control and
   nobody else any access (auth.dat, audit.log and the device lists live here). */
BOOL LgDataPath(const wchar_t* file, wchar_t* out, size_t cch);

#ifdef __cplusplus
}
#endif
