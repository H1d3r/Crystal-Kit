#define NT_SUCCESS(status) ( ( NTSTATUS ) ( status ) >= 0 )
#define NtCurrentProcess() ( ( HANDLE ) ( ULONG_PTR ) -1 )

typedef struct {
    ULONG ExtendedProcessInfo;
    ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION;

typedef enum {
    ProcessUserModeIOPL = 16,
    ProcessCookie = 36
} PROCESSINFOCLASS;

typedef struct {
    DWORD                 dwNumberOfOffsets;
    PULONG                plOutput;
    PCFG_CALL_TARGET_INFO ptOffsets;
    PVOID                 pMustBeZero;
    PVOID                 pMoarZero;
} VM_INFORMATION;

typedef enum {
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY;

typedef enum {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

BOOL cfg_enabled ( );
BOOL bypass_cfg ( PVOID address );