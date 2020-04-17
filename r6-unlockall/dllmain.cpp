#include <Windows.h>
#include <iostream>

constexpr ::std::ptrdiff_t function_off = 0x11335f0; //01-21-2020

void writeProtectedBytes(BYTE *const adr, const BYTE *const shell, const size_t size)
{
	DWORD old;
	VirtualProtect(adr, sizeof(BYTE), PAGE_READWRITE, &old);
	memcpy(adr, shell, size);
	VirtualProtect(adr, sizeof(BYTE), old, &old);
}

void writeProtectedBytes(BYTE *const adr, BYTE shell)
{
	writeProtectedBytes(adr, &shell, 1);
}

void dllthread(const HMODULE hModule) {


	//Allocating console
	AllocConsole();
	(void)freopen("CONOUT$", "w", stdout);

	std::cout << "[UNLOCK ALL]" << '\n' << 
				 "------------" << std::endl;

	constexpr BYTE NOP = 0x90;
	constexpr BYTE RET = 0xC3;

	//shell to stop Rainbow from terminating itself
	constexpr BYTE shell[3] { RET, NOP, NOP }; //two nops even needed?
	
	BYTE *const terminate = reinterpret_cast<BYTE*>(TerminateProcess);
	std::cout << "TerminateProcess at: " << std::hex << terminate << std::endl;

	writeProtectedBytes(terminate, shell, sizeof(shell));

	std::cout << "Function offset: " << std::hex << function_off << std::endl;
	uintptr_t function = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)) + function_off;
	std::cout << "Function : " << std::hex << function << std::endl;
	BYTE *const adr1 = reinterpret_cast<BYTE*>(function + 0x23C);
	BYTE *const adr2 = reinterpret_cast<BYTE*>(function + 0x259);
	std::cout << "Swapped" << std::endl;

	writeProtectedBytes(adr1, 0x25); //8bit add?
	writeProtectedBytes(adr2, 0x00); //32bit and?

	std::cout << "Everything unlocked!" << std::endl;
	
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
}



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	void* lpReserved
) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) 
	{
		CloseHandle(CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(dllthread), hModule, 0, nullptr));
	}
	return TRUE;
}
