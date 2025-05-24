// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "CommR3.h"
#include "Api.h"



PVOID MyReadFile(WCHAR* fileName, PULONG fileSize)
{
	HANDLE fileHandle = NULL;
	DWORD readd = 0;
	PVOID fileBufPtr = NULL;

	fileHandle = CreateFileW(
		fileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		*fileSize = 0;
		return NULL;
	}

	*fileSize = GetFileSize(fileHandle, NULL);

	fileBufPtr = calloc(1, *fileSize);

	if (!ReadFile(fileHandle, fileBufPtr, *fileSize, &readd, NULL))
	{
		free(fileBufPtr);
		fileBufPtr = NULL;
		*fileSize = 0;
	}

	CloseHandle(fileHandle);
	return fileBufPtr;

}

int main(int argc, char * argv[])
{
	if (SH_DriverLoad())
	{

		PVOID	dllx86Ptr = NULL;
		ULONG	dllx86Size = 0;
		dllx86Ptr = MyReadFile(L"DllTestX86.dll", &dllx86Size);
		printf("dllx86Ptr  === %p\r\n", dllx86Ptr);
		printf("dllx86Size ====%d\r\n", dllx86Size);
		SH_DllInjectX86(6336,dllx86Ptr, dllx86Size);
		system("pause");
		PVOID	dllx64Ptr = NULL;
		ULONG	dllx64Size = 0;
		dllx64Ptr = MyReadFile(L"DllTestX64.dll", &dllx64Size);
		printf("dllx64Ptr  === %p\r\n", dllx64Ptr);
		printf("dllx64Size ====%x\r\n", dllx64Size);
		SH_DllInjectX64(6296, dllx64Ptr, dllx64Size);
		SH_UnDriverLoad();
	}
	else 
	{
		printf("驱动加载失败\r\n");
	}
	


	system("pause");
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

