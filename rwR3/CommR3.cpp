#include "CommR3.h"
#include <intrin.h>
#include "../rw/comm/commStruct.h"
#include <stdio.h>

typedef struct _IO_STATUS_BLOCK {
	union {
		ULONG Status;
		PVOID Pointer;
	};

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef ULONG(WINAPI *NtQueryInformationFileProc)(
	__in HANDLE FileHandle,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__out_bcount(Length) PVOID FileInformation,
	__in ULONG Length,
	__in ULONG FileInformationClass);

typedef ULONG(WINAPI * NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)(char a1, PVOID a2, PVOID a3, PVOID a4);

NtQueryInformationFileProc gNtQueryInformationFile = NULL;
HANDLE ghFile = NULL;

NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc gNtConvertBetweenAuxiliary = NULL;


USHORT MyGetVersion()
{
	static USHORT osBuildNumber = 0;
	if (osBuildNumber) return osBuildNumber;
#ifndef _WIN64
	DWORD peb = __readfsdword(0x30);
	osBuildNumber = *(PUSHORT)(peb + 0xac);
#else
	ULONG64 peb = __readgsqword(0x60);
	osBuildNumber = *(PUSHORT)(peb + 0x120);
#endif

	return osBuildNumber;
}

BOOLEAN DriverCommInit()
{

	if(gNtQueryInformationFile || gNtConvertBetweenAuxiliary) return TRUE;

	USHORT buildNumber = MyGetVersion();
	HMODULE h = GetModuleHandleA("ntdll.dll");
	if (buildNumber == 7600 || buildNumber == 7601)
	{
		gNtQueryInformationFile = (NtQueryInformationFileProc)GetProcAddress(h, "NtQueryInformationFile");
		char bufPath[MAX_PATH] = { 0 };
		
		GetTempPathA(MAX_PATH, bufPath);
		strcat_s(bufPath, "\\1.txt");
		ghFile = CreateFileA(bufPath, FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (ghFile == NULL || ghFile == INVALID_HANDLE_VALUE)
		{
			MessageBoxA(NULL, "通信初始化失败", "func", 0);
			return FALSE;
		}
	}
	else 
	{
		
		gNtConvertBetweenAuxiliary = (NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)GetProcAddress(h, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	}

	return TRUE;
}

BOOLEAN DriverComm7(ULONG cmd, PVOID inData, SIZE_T size)
{
	char buf[0xE0] = { 0 };

	PCommPackage package = (PCommPackage)buf;
	package->Id = 0x12345678;
	package->cmd = cmd;
	package->Size = size;
	package->Data = (ULONG64)inData;
	package->retStatus = -1;
	IO_STATUS_BLOCK is = { 0 };
	gNtQueryInformationFile(ghFile, &is, buf, sizeof(buf), 0x34);

	return package->retStatus == 0;
}


BOOLEAN DriverComm10(ULONG cmd, PVOID inData, SIZE_T size)
{

	CommPackage package;
	package.Id = 0x12345678;
	package.cmd = cmd;
	package.Data = (ULONG64)inData;
	package.Size = size;
	package.retStatus = -1;
	ULONG64 xxx = 0;
	PCommPackage data = &package;
	gNtConvertBetweenAuxiliary(1, (PVOID)&data, (PVOID)&xxx, NULL);

	printf("驱动返回 = %d\r\n", package.retStatus);

	return package.retStatus == 0;
}

//int x = DriverCommInit();

BOOLEAN DriverComm(ULONG cmd, PVOID inData, SIZE_T size)
{
	if (DriverCommInit())
	{
		USHORT buildNumber = MyGetVersion();
		if (buildNumber == 7600 || buildNumber == 7601)
		{
			return DriverComm7(cmd, inData, size);
		}
		else 
		{
			return DriverComm10(cmd, inData, size);
		}
	}

	return FALSE;
}