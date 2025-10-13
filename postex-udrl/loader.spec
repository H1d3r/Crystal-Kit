name     "Crystal Kit Postex UDRL"
describe "Evasion Kit for Cobalt Strike"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic
	
	load "bin/proxy.x64.o"
		make pic
		export
		preplen
		link "draugr"

		load "bin/hook.x64.o"
			make object
			import "LoadLibraryA, GetProcAddress, SpoofStub, RtlLookupFunctionEntry, GetModuleHandleA, VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, VirtualFree, GetThreadContext, SetThreadContext, ResumeThread, CreateThread, CreateRemoteThread, OpenProcess, OpenThread, CloseHandle, CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualQuery, DuplicateHandle, ReadProcessMemory, WriteProcessMemory, ExitThread, CreateProcessA, Sleep"
			export
			link "hooks"

		push $DLL
			link "postex"
	
		export
