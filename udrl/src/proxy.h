#include <windows.h>

typedef struct _DRAUGR_PARAMETERS {
    PVOID       Fixup;                                 // 0
    PVOID       OriginalReturnAddress;                 // 8
    PVOID       Rbx;                                   // 16
    PVOID       Rdi;                                   // 24
    PVOID       BaseThreadInitThunkStackSize;          // 32
    PVOID       BaseThreadInitThunkReturnAddress;      // 40
    PVOID       TrampolineStackSize;                   // 48
    PVOID       RtlUserThreadStartStackSize;           // 56
    PVOID       RtlUserThreadStartReturnAddress;       // 64
    PVOID       Ssn;                                   // 72
    PVOID       Trampoline;                            // 80
    PVOID       Rsi;                                   // 88
    PVOID       R12;                                   // 96
    PVOID       R13;                                   // 104
    PVOID       R14;                                   // 112
    PVOID       R15;                                   // 120
} DRAUGR_PARAMETERS, * PDRAUGR_PARAMETERS;

typedef PVOID (*DRAUGR)(PVOID, PVOID, PVOID, PVOID, PDRAUGR_PARAMETERS, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);