#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LG_LAYER_COUNT      16
#define LG_LAYER_KERNEL     15
#define LG_MAX_RAISE_STEP   4   /* one elevation may climb at most this many layers */

typedef enum {
    LG_ISO_APPCONTAINER = 0,    /* AppContainer + Job Object (layers 0-3)            */
    LG_ISO_RESTRICTED,          /* restricted token, Medium/Low integrity (4-11)     */
    LG_ISO_HIGH,                /* privilege-stripped token, High integrity (12-14)  */
    LG_ISO_RESERVED             /* layer 15: kernel/root, never used for user apps   */
} LgIsolation;

#define LG_F_NET        0x1     /* outbound internet                                  */
#define LG_F_CLIPBOARD  0x2     /* clipboard access                                   */
#define LG_F_UI_FULL    0x4     /* no Job Object UI restrictions                      */

typedef struct {
    int          id;
    const wchar_t* name;
    LgIsolation  iso;
    DWORD        integrityRid;  /* SECURITY_MANDATORY_*_RID                           */
    unsigned     memMB;         /* per-process memory cap (0 = unlimited)             */
    unsigned     maxProcs;      /* active processes in the layer's shared Job         */
    unsigned     cpuPct;        /* hard CPU cap for the whole layer (0/100 = none)    */
    unsigned     flags;
} LgLayer;

const LgLayer* LgGetLayer(int id);

typedef enum {
    LG_POL_OK = 0,
    LG_POL_SAME,
    LG_POL_RANGE,
    LG_POL_RESERVED,
    LG_POL_JUMP
} LgPolicy;

/* Pure policy check. Lowering a layer is always allowed; raising is limited to
   LG_MAX_RAISE_STEP layers at a time and can never reach layer 15. */
LgPolicy      LgCheckTransition(int from, int to);
BOOL          LgNeedsAuth(int from, int to);       /* TRUE when privileges increase */
const wchar_t* LgPolicyText(LgPolicy p);

#ifdef __cplusplus
}
#endif
