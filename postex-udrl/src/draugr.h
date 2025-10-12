#include <windows.h>

#define RBP_OP_INFO 0x5
#define draugrArg(i) (ULONG_PTR)functionCall->args[i]

typedef ULONG NTAPI (*RTLRANDOMEX) (PULONG);

// God Bless Vulcan Raven.
typedef struct _STACK_FRAME {
    LPCWSTR    DllPath;
    ULONG      Offset;
    ULONGLONG  TotalStackSize;
    BOOL       RequiresLoadLibrary;
    BOOL       SetsFramePointer;
    PVOID      ReturnAddress;
    BOOL       PushRbp;
    ULONG      CountOfCodes;
    BOOL       PushRbpIndex;
} STACK_FRAME, * PSTACK_FRAME;

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SAVE_XMM128 = 8,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union _UNWIND_CODE {
	struct {
		UBYTE CodeOffset;
		UBYTE UnwindOp : 4;
		UBYTE OpInfo   : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UBYTE Version : 3;
	UBYTE Flags   : 5;
	UBYTE SizeOfProlog;
	UBYTE CountOfCodes;
	UBYTE FrameRegister : 4;
	UBYTE FrameOffset   : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _FRAME_INFO {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO, * PFRAME_INFO;

typedef struct _SYNTHETIC_STACK_FRAME {
    FRAME_INFO Frame1;
    FRAME_INFO Frame2;
    PVOID      pGadget;
} SYNTHETIC_STACK_FRAME, * PSYNTHETIC_STACK_FRAME;

typedef struct {
    PVOID function;
    int argc;
    ULONG_PTR args[10];
} FUNCTION_CALL, * PFUNCTION_CALL;

typedef struct _DRAUGR_FUNCTION_CALL {
    PFUNCTION_CALL FunctionCall;
    PVOID StackFrame;
    PVOID SpoofCall;
} DRAUGR_FUNCTION_CALL, *PDRAUGR_FUNCTION_CALL;