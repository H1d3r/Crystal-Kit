#include <windows.h>
#include "memory.h"

void applyxor(char * data, DWORD len);
void xorsection(MEMORY_SECTION * section, BOOL mask);
void xorregion(MEMORY_REGION * region, BOOL mask);
void xormemory(BOOL mask);