#include "audit.h"
#include "paths.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HEXLEN 64

static CRITICAL_SECTION   g_cs;
static volatile LONG      g_csState = 0;      /* 0 = not created, 1 = creating, 2 = ready */
static BOOL               g_ready = FALSE;
static wchar_t            g_path[MAX_PATH];
static char               g_prev[HEXLEN + 1];
static unsigned long long g_seq = 0;

static void Sha256Hex(const char* data, size_t len, char out[HEXLEN + 1])
{
    static const char* hx = "0123456789abcdef";
    UCHAR h[32];
    int i;
    if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0,
                                   (PUCHAR)data, (ULONG)len, h, sizeof(h)))) {
        memset(out, 'x', HEXLEN);           /* never matches a real digest */
        out[HEXLEN] = 0;
        return;
    }
    for (i = 0; i < 32; i++) {
        out[i * 2]     = hx[h[i] >> 4];
        out[i * 2 + 1] = hx[h[i] & 15];
    }
    out[HEXLEN] = 0;
}

/* Splits "a\tb\tc\td\te" in place. Returns 1 on success. */
static int ParseLine(char* line, char* f[5])
{
    int n = 0;
    char* p = line;
    size_t l = strlen(line);
    while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
    f[n++] = p;
    while (*p && n < 5) {
        if (*p == '\t') { *p = 0; f[n++] = p + 1; }
        p++;
    }
    return n == 5;
}

BOOL LgAuditInit(void)
{
    FILE* f = NULL;
    char line[2048];

    if (InterlockedCompareExchange(&g_csState, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
        g_csState = 2;
    }
    while (g_csState != 2) Sleep(1);

    EnterCriticalSection(&g_cs);
    if (!LgDataPath(L"audit.log", g_path, MAX_PATH)) {
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }
    memset(g_prev, '0', HEXLEN);
    g_prev[HEXLEN] = 0;
    g_seq = 0;

    /* Continue the existing chain after a restart. */
    if (_wfopen_s(&f, g_path, L"rb") == 0 && f) {
        while (fgets(line, sizeof(line), f)) {
            char* t[5];
            if (ParseLine(line, t)) {
                g_seq = strtoull(t[0], NULL, 10) + 1;
                strcpy_s(g_prev, sizeof(g_prev), t[4]);
            }
        }
        fclose(f);
    }
    g_ready = TRUE;
    LeaveCriticalSection(&g_cs);
    return TRUE;
}

void LgAuditWrite(const wchar_t* fmt, ...)
{
    wchar_t wmsg[700];
    char msg[1500], body[1800], hash[HEXLEN + 1], line[2000];
    va_list ap;
    int i, bl, ll;
    HANDLE h;
    DWORD written = 0;

    if (!g_ready) return;

    va_start(ap, fmt);
    _vsnwprintf_s(wmsg, _countof(wmsg), _TRUNCATE, fmt, ap);
    va_end(ap);
    for (i = 0; wmsg[i]; i++)
        if (wmsg[i] == L'\t' || wmsg[i] == L'\r' || wmsg[i] == L'\n') wmsg[i] = L' ';
    if (WideCharToMultiByte(CP_UTF8, 0, wmsg, -1, msg, sizeof(msg), NULL, NULL) <= 0)
        strcpy_s(msg, sizeof(msg), "?");

    EnterCriticalSection(&g_cs);

    bl = _snprintf_s(body, sizeof(body), _TRUNCATE, "%llu\t%lld\t%s\t%s",
                     g_seq, (long long)time(NULL), msg, g_prev);
    if (bl > 0) {
        Sha256Hex(body, (size_t)bl, hash);
        ll = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s\t%s\n", body, hash);

        /* append-only handle: FILE_APPEND_DATA without FILE_WRITE_DATA */
        h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            if (ll > 0 && WriteFile(h, line, (DWORD)ll, &written, NULL) && written == (DWORD)ll) {
                strcpy_s(g_prev, sizeof(g_prev), hash);
                g_seq++;
            }
            CloseHandle(h);
        }
    }
    LeaveCriticalSection(&g_cs);
}

BOOL LgAuditVerify(long long* badLine, long long* total)
{
    FILE* f = NULL;
    char line[2048], prev[HEXLEN + 1], body[1800], calc[HEXLEN + 1];
    long long n = 0;
    BOOL ok = TRUE;

    if (badLine) *badLine = 0;
    if (total) *total = 0;
    if (!g_ready) return FALSE;

    memset(prev, '0', HEXLEN);
    prev[HEXLEN] = 0;

    EnterCriticalSection(&g_cs);
    if (_wfopen_s(&f, g_path, L"rb") != 0 || !f) {
        LeaveCriticalSection(&g_cs);
        return TRUE;                        /* no log yet: nothing to verify */
    }
    while (fgets(line, sizeof(line), f)) {
        char* t[5];
        int bl;
        n++;
        if (!ParseLine(line, t) || strcmp(t[3], prev) != 0) { ok = FALSE; break; }
        bl = _snprintf_s(body, sizeof(body), _TRUNCATE, "%s\t%s\t%s\t%s", t[0], t[1], t[2], t[3]);
        if (bl <= 0) { ok = FALSE; break; }
        Sha256Hex(body, (size_t)bl, calc);
        if (strcmp(calc, t[4]) != 0) { ok = FALSE; break; }
        strcpy_s(prev, sizeof(prev), t[4]);
    }
    fclose(f);
    LeaveCriticalSection(&g_cs);

    if (total) *total = n;
    if (!ok && badLine) *badLine = n;
    return ok;
}
