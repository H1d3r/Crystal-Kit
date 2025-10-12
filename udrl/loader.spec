name     "Crystal Kit"
describe ""
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic
	
	load "bin/proxy.x64.o"
		make pic
		export
		preplen
		link "my_proxy"

		generate $HKEY 128

		load "bin/hook.x64.o"
			make object
			patch "xorkey" $HKEY
			import "LoadLibraryA, GetProcAddress, SpoofStub, RtlLookupFunctionEntry, GetModuleHandleA, VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, VirtualFree, GetThreadContext, SetThreadContext, ResumeThread, CreateThread, CreateRemoteThread, OpenProcess, OpenThread, CloseHandle, CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualQuery, DuplicateHandle, ReadProcessMemory, WriteProcessMemory, ExitThread, CreateProcessA, Sleep"
			export
			link "my_hooks"

		push $DLL
			link "my_data"
	
		export
