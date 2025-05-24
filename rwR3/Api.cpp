#include "Api.h"
#include "LoadDriver.h"
#include <time.h>
#include "../rw/comm/commStruct.h"
#include "CommR3.h"
#include <iostream>
#include <windows.h>
char AZTable[62]=
{
	0,
};

void initTable()
{
	if (AZTable[0] != 0) return;
	int k = 0;
	for (char i = 'A'; i <= 'Z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = 'a'; i <= 'z'; i++, k++)
	{
		AZTable[k] = i;
	}

	for (char i = '0'; i <= '9'; i++, k++)
	{
		AZTable[k] = i;
	}
}

char * GetRandName()
{
	static char * name = NULL;
	if (name) return name;

	initTable();

	name = (char *)malloc(20);

	memset(name, 0, 20);  //15 .sys 0

	time_t t = time(NULL);
	srand(t);
	
	int len = (rand() % 10) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}
	
	strcat(name, ".sys");

	return name;
}

char * GetRandServiceName()
{
	static char * name = NULL;
	if (name) return name;

	initTable();

	name = (char *)malloc(10);

	memset(name, 0, 10);  //15 .sys 0

	time_t t = time(NULL);
	srand(t);

	int len = (rand() % 4) + 5;
	for (int i = 0; i < len; i++)
	{
		int index = rand() % sizeof(AZTable);
		name[i] = AZTable[index];
	}

	return name;
}

EXTERN_C BOOLEAN WINAPI SH_Test()
{
	ULONG64 xx = 0;
	return DriverComm(CMD_TEST, &xx, sizeof(xx));

	
}

//cdcel __stdcall
EXTERN_C BOOLEAN WINAPI SH_DriverLoad()
{
	return TRUE;

	LoadDriver Load;

	if (SH_Test())
	{
		return TRUE;
	}

	//char bufPath[MAX_PATH] = { 0 };
	//GetTempPathA(MAX_PATH, bufPath);
	char buffer[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, buffer);
	char * driverName = "\\rw.sys";
	char * serviceName = "WINDr";
	strcat(buffer, driverName);
	printf("Çý¶¯Â·¾¶= %s\r\n", buffer);


	Load.installDriver(buffer, serviceName);


	return SH_Test();
}

EXTERN_C VOID WINAPI SH_UnDriverLoad()
{
	LoadDriver Load;
	
	char * serviceName = GetRandServiceName();
	
	Load.unload(serviceName);
}


EXTERN_C ULONG64 WINAPI SH_GetModule(DWORD pid, char * moduleName)
{
	ModuleInfo info = {0};
	info.moduleName = (ULONG64)moduleName;
	info.pid = pid;
	DriverComm(CMD_GET_MODULE, &info, sizeof(ModuleInfo));

	return info.Module;
}


EXTERN_C BOOLEAN WINAPI SH_ReadMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size)
{
	ReadWriteInfo info = {0};
	info.pid = pid;
	info.BaseAddress = BaseAddress;
	info.Buffer = (ULONG64)Buffer;
	info.size = size;

	return DriverComm(CMD_READ_MEMORY, &info, sizeof(ReadWriteInfo));
}

EXTERN_C BOOLEAN WINAPI SH_WriteMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size)
{
	ReadWriteInfo info = { 0 };
	info.pid = pid;
	info.BaseAddress = BaseAddress;
	info.Buffer = (ULONG64)Buffer;
	info.size = size;

	return DriverComm(CMD_WRITE_MEMORY, &info, sizeof(ReadWriteInfo));
}

EXTERN_C BOOLEAN WINAPI SH_QueryMemory(DWORD pid, ULONG64 BaseAddress, PMMEMORY_BASIC_INFORMATION pinfo)
{
	QueryMemoryInfo info = { 0 };
	info.pid = pid;
	info.BaseAddress = BaseAddress;
	
	BOOLEAN isRet = DriverComm(CMD_QUERY_MEMORY, &info, sizeof(QueryMemoryInfo));

	memcpy(pinfo, &info.memoryInfo, sizeof(MMEMORY_BASIC_INFORMATION));

	return isRet;
}

EXTERN_C BOOLEAN WINAPI SH_ProtectProcess(DWORD pid)
{
	ProtectInfo info;
	info.pid = pid;

	return DriverComm(CMD_PROTECT_PROCESS, &info, sizeof(ProtectInfo));
}

EXTERN_C BOOLEAN WINAPI SH_RemoteCall(DWORD pid,PVOID shellcode,DWORD shellcodeSize)
{
	RemoteCallInfo info;
	info.pid = pid;
	info.shellcode = (ULONG64)shellcode;
	info.shellcodeSize = shellcodeSize;

	return DriverComm(CMD_REMOTE_CALL, &info, sizeof(ProtectInfo));
}

EXTERN_C BOOLEAN WINAPI SH_DllInjectX86(DWORD pid,PVOID inBuf, ULONG64 buffSize)
{
	DllInject dllInfo;
	dllInfo.pid = pid;
	dllInfo.dllBuff = inBuf;
	dllInfo.dllBuffSize = buffSize;
	return DriverComm(CMD_Dll_Inject_X86, &dllInfo, sizeof(dllInfo));
}

EXTERN_C BOOLEAN WINAPI SH_DllInjectX64(DWORD pid, PVOID inBuf, ULONG64 buffSize)
{
	DllInject dllInfo;
	dllInfo.pid = pid;
	dllInfo.dllBuff = inBuf;
	dllInfo.dllBuffSize = buffSize;
	return DriverComm(CMD_Dll_Inject_X64, &dllInfo, sizeof(dllInfo));
}