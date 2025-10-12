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
 
/*
 * Save you some headache doing a PIC printf for debugging
 */
#ifndef WIN32_FUNC
#define WIN32_FUNC( x ) __typeof__( x ) * x
#endif

#define PIC_STRING(name, str) char name[] = { str }
#define PIC_WSTRING(name, str) wchar_t name[] = { str }
 
typedef int __cdecl (*vsnprintf_t)(char * d, size_t n, char * format, ...);
 
typedef struct {
    WIN32_FUNC(VirtualAlloc);
    WIN32_FUNC(VirtualFree);
    WIN32_FUNC(OutputDebugStringA);
    vsnprintf_t vsnprintf;
} DPRINTFFUNCS;
 
void __dprintf(DPRINTFFUNCS * funcs, char * format, va_list * args) {
    int    len;
    char * temp;
 
    /* figure out the length of our buffer */
    len  = funcs->vsnprintf(NULL, 0, format, *args);
 
    /* allocate our memory */
    temp = funcs->VirtualAlloc(NULL, len + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (temp == NULL) {
        return;
    }
    //__stosb((unsigned char *)temp, 0, len + 1);
 
    /* format everything */
    funcs->vsnprintf(temp, len + 1, format, *args);
 
    /* printf it */
    funcs->OutputDebugStringA(temp);
 
    /* free our memory and move on with our lives */
    funcs->VirtualFree(temp, 0, MEM_RELEASE);
}
 
void dprintf(IMPORTFUNCS * ifuncs, char * format, ...) {
    va_list args;
    HMODULE mod;
 
    DPRINTFFUNCS funcs;
 
    PIC_STRING(kern32, "KERNEL32");
    PIC_STRING(vastr,  "VirtualAlloc");
    PIC_STRING(vfstr,  "VirtualFree");
    PIC_STRING(odstr,  "OutputDebugStringA");
    PIC_STRING(msvcrt, "MSVCRT"); 
    PIC_STRING(pfstr,  "vsnprintf");
 
    mod                      = ifuncs->LoadLibraryA(kern32);
    funcs.VirtualAlloc       = (__typeof__(VirtualAlloc) *)      ifuncs->GetProcAddress(mod, vastr);
    funcs.VirtualFree        = (__typeof__(VirtualFree) *)       ifuncs->GetProcAddress(mod, vfstr);
    funcs.OutputDebugStringA = (__typeof__(OutputDebugStringA) *)ifuncs->GetProcAddress(mod, odstr);
 
    mod                      = ifuncs->LoadLibraryA(msvcrt);
    funcs.vsnprintf          = (vsnprintf_t)                     ifuncs->GetProcAddress(mod, pfstr);
 
    va_start(args, format);
    __dprintf(&funcs, format, &args);
    va_end(args);
}