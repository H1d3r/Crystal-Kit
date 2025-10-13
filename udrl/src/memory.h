#include <windows.h>

typedef struct {
    void * baseAddress;
    SIZE_T size;
    DWORD  currentProtect;
    DWORD  previousProtect;
} MEMORY_SECTION;

typedef struct {
    void *         baseAddress;
    SIZE_T         size;
    MEMORY_SECTION sections[5];
} MEMORY_REGION;

typedef struct {
    MEMORY_REGION pic;
    MEMORY_REGION hooks;
    MEMORY_REGION beacon;
} MEMORY_LAYOUT;