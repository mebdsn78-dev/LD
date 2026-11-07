#include "layers.h"

#define IL_LOW   SECURITY_MANDATORY_LOW_RID
#define IL_MED   SECURITY_MANDATORY_MEDIUM_RID
#define IL_HIGH  SECURITY_MANDATORY_HIGH_RID
#define ISO_AC    LG_ISO_APPCONTAINER
#define ISO_RS    LG_ISO_RESTRICTED
#define ISO_HI    LG_ISO_HIGH
#define F_CLIP  LG_F_CLIPBOARD
#define F_NET   LG_F_NET
#define F_FULL  LG_F_UI_FULL

/* id, name, isolation, integrity, memMB, procs, cpu%, flags */
static const LgLayer kLayers[LG_LAYER_COUNT] = {
    {  0, L"Untrusted Shared Sandbox", ISO_AC, IL_LOW,  256,  16,  25, 0 },
    {  1, L"Restricted Viewer",        ISO_AC, IL_LOW,  512,  16,  40, 0 },
    {  2, L"Offline Productivity",     ISO_AC, IL_LOW, 1024,  32,  50, F_CLIP },
    {  3, L"Basic Network",            ISO_AC, IL_LOW, 1024,  32,  60, F_CLIP | F_NET },
    {  4, L"Media Playback",           ISO_RS, IL_MED, 2048,  64,  70, F_CLIP | F_NET },
    {  5, L"Communications",           ISO_RS, IL_MED, 2048,  64,  70, F_CLIP | F_NET },
    {  6, L"Browser (Content)",        ISO_RS, IL_LOW, 4096, 128,  80, F_CLIP | F_NET },
    {  7, L"Browser (Main)",           ISO_RS, IL_MED, 4096, 128,  90, F_CLIP | F_NET },
    {  8, L"Camera / Capture",         ISO_RS, IL_MED, 2048,  32,  70, F_CLIP | F_NET },
    {  9, L"Developer Tools",          ISO_RS, IL_MED, 8192, 256, 100, F_CLIP | F_NET | F_FULL },
    { 10, L"File Manager",             ISO_RS, IL_MED, 2048,  64,  70, F_CLIP | F_FULL },
    { 11, L"Package / Update Client",  ISO_RS, IL_MED, 2048,  64,  80, F_CLIP | F_NET | F_FULL },
    { 12, L"System Utilities",         ISO_HI, IL_HIGH, 4096, 128, 100, F_CLIP | F_NET | F_FULL },
    { 13, L"Network Administration",   ISO_HI, IL_HIGH, 4096, 128, 100, F_CLIP | F_NET | F_FULL },
    { 14, L"Security / Backup Tools",  ISO_HI, IL_HIGH, 0,    128, 100, F_CLIP | F_NET | F_FULL },
    { 15, L"Kernel / Root (reserved)", LG_ISO_RESERVED, 0, 0, 0, 0, F_FULL }
};

const LgLayer* LgGetLayer(int id)
{
    if (id < 0 || id >= LG_LAYER_COUNT) return NULL;
    return &kLayers[id];
}

LgPolicy LgCheckTransition(int from, int to)
{
    if (from < 0 || from >= LG_LAYER_COUNT || to < 0 || to >= LG_LAYER_COUNT)
        return LG_POL_RANGE;
    if (to == from)
        return LG_POL_SAME;
    if (to == LG_LAYER_KERNEL)
        return LG_POL_RESERVED;
    if (to > from && (to - from) > LG_MAX_RAISE_STEP)
        return LG_POL_JUMP;
    return LG_POL_OK;
}

BOOL LgNeedsAuth(int from, int to)
{
    return to > from;
}

const wchar_t* LgPolicyText(LgPolicy p)
{
    switch (p) {
    case LG_POL_OK:       return L"allowed";
    case LG_POL_SAME:     return L"The app is already in this layer.";
    case LG_POL_RANGE:    return L"Layer out of range.";
    case LG_POL_RESERVED: return L"Layer 15 (Kernel/Root) is reserved and cannot be assigned to applications.";
    case LG_POL_JUMP:     return L"Too large a jump. Raise the layer in steps of at most 4; every step is authenticated and audited separately.";
    }
    return L"denied";
}
