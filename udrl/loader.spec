name     "Crystal Kit UDRL"
describe "Evasion Kit for Cobalt Strike"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize
		dfr "resolve" "ror13"
		mergelib "../libtcg.x64.zip"
		mergelib "../libtp.x64.zip"
	
	load "bin/proxy.x64.o"
		make pic
		export
		preplen
		link "draugr"

	generate $KEY 128

	load "bin/hook.x64.o"
		make object +optimize
		mergelib "../libtcg.x64.zip"
		patch "xorkey" $KEY
		import "LoadLibraryA, GetProcAddress, SpoofStub, VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, VirtualFree, VirtualQuery, GetThreadContext, SetThreadContext, ResumeThread, CreateThread, CreateRemoteThread, OpenProcess, OpenThread, ExitThread, CloseHandle, Sleep, CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, DuplicateHandle, ReadProcessMemory, WriteProcessMemory, CreateProcessA"
		export
		link "hooks"

	push $DLL
		link "dll"
	
	export
