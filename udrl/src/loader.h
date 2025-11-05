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

#include <windows.h>
#include "tcg.h"
#include "memory.h"

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);

#define GETRESOURCE(x) (char *)&x

typedef struct {
    int   length;
    char  value[];
} RESOURCE;

typedef struct {
    #if DEBUG
    char data[8192];
    char code[16384];
    #else
    char data[4096];
    char code[16384];
    #endif
} PICO;

DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAlloc         (LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAllocEx       (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtect       (LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtectEx     (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualFree          (LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT SIZE_T   WINAPI KERNEL32$VirtualQuery         (LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$GetThreadContext     (HANDLE, LPCONTEXT);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetThreadContext     (HANDLE, const CONTEXT *);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$ResumeThread         (HANDLE);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateThread         (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateRemoteThread   (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenProcess          (DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenThread           (DWORD, BOOL, DWORD);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$ExitThread           (DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle          (HANDLE);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$Sleep                (DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileMappingA   (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$MapViewOfFile        (HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$UnmapViewOfFile      (LPCVOID);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DuplicateHandle      (HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadProcessMemory    (HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$WriteProcessMemory   (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CreateProcessA       (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtAllocateVirtualMemory (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtProtectVirtualMemory  (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtFreeVirtualMemory     (HANDLE, PVOID *, PSIZE_T, ULONG);

typedef void (*PICOHOOK_ENTRY)(IMPORTFUNCS *, MEMORY_LAYOUT *);

char * resolve(DWORD modHash, DWORD funcHash) {
    char * hModule = (char *)findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}