#include <windows.h>

WINBASEAPI int    STDAPIVCALLTYPE MSVCRT$vsnprintf           (char *, size_t, const char *, ...);
WINBASEAPI LPVOID WINAPI         KERNEL32$VirtualAlloc       (LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI VOID   WINAPI         KERNEL32$OutputDebugStringA (LPCSTR);
WINBASEAPI BOOL   WINAPI         KERNEL32$VirtualFree        (LPVOID, SIZE_T, DWORD);

void dprintf(char * format, ...)
{
    va_list args;
    va_start(args, format);

    int    len  = MSVCRT$vsnprintf(NULL, 0, format, args);
    char * temp = (char *)KERNEL32$VirtualAlloc(NULL, len + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    if (temp == NULL) {
        return;
    }

    MSVCRT$vsnprintf(temp, len + 1, format, args);
    KERNEL32$OutputDebugStringA(temp);
    KERNEL32$VirtualFree(temp, 0, MEM_RELEASE);

    va_end(args);
}