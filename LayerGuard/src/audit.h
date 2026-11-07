#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tamper-evident audit log: every line carries the SHA-256 of the previous
   line, so editing, deleting or reordering an entry breaks the chain.
   Line format (UTF-8, tab separated):
       seq <TAB> unix_time <TAB> message <TAB> prev_hash <TAB> hash          */

BOOL LgAuditInit(void);
void LgAuditWrite(const wchar_t* fmt, ...);               /* thread-safe */

/* Re-computes the whole chain. Returns TRUE if intact. *badLine is the
   1-based line that failed (0 when intact) and *total the lines checked. */
BOOL LgAuditVerify(long long* badLine, long long* total);

#ifdef __cplusplus
}
#endif
