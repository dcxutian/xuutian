#pragma once

#ifndef _WINDOWS
#include <ntifs.h>
#else
#include <Windows.h>
#endif
typedef struct _CommPackage
{
	ULONG64 Id; // 1 2 3 4
	ULONG64 cmd; // 1 2 3 4
	ULONG64 Data;
	ULONG64 Size;
	ULONG64 retStatus;
}CommPackage, *PCommPackage;

typedef enum _CMD
{
	CMD_TEST,		//防止驱动隐藏之后 重复加载
	CMD_GET_MODULE, //获取模块
	CMD_READ_MEMORY, //读内存
	CMD_WRITE_MEMORY, //写内存
	CMD_QUERY_MEMORY, //查询内存
	CMD_PROTECT_PROCESS, //保护进程
	CMD_REMOTE_CALL,	 //远程CALL
	CMD_Dll_Inject_X86,	 //DLL注入
	CMD_Dll_Inject_X64,	 //DLL注入
}CMD;


typedef struct _ModuleInfo 
{
	ULONG64 pid;
	ULONG64 moduleName;
	ULONG64 Module;
	ULONG64 ModuleSize;
}ModuleInfo,*PModuleInfo;

typedef struct _ReadWriteInfo 
{
	ULONG64 pid;
	ULONG64 BaseAddress;
	ULONG64 Buffer;
	ULONG64 size;
}ReadWriteInfo,*PReadWriteInfo;

typedef struct _MyMEMORY_BASIC_INFORMATION {
	ULONG64 BaseAddress;
	ULONG64 AllocationBase;
	ULONG64 AllocationProtect;
	ULONG64 RegionSize;
	ULONG64 State;
	ULONG64 Protect;
	ULONG64 Type;
} MyMEMORY_BASIC_INFORMATION, *PMyMEMORY_BASIC_INFORMATION;

typedef struct _QueryMemoryInfo
{
	ULONG64 pid;
	ULONG64 BaseAddress;
	MyMEMORY_BASIC_INFORMATION memoryInfo;
}QueryMemoryInfo, *PQueryMemoryInfo;

typedef struct _ProtectInfo
{
	ULONG64 pid;

}ProtectInfo, *PProtectInfo;

typedef struct _RemoteCallInfo
{
	ULONG64 pid;
	ULONG64 shellcode;
	ULONG64 shellcodeSize;
}RemoteCallInfo, *PRemoteCallInfo;

typedef ULONG (NTAPI * CommCallbackProc)(PCommPackage package);



typedef struct _DllInject {

	ULONG64 pid;
	PVOID dllBuff;
	SIZE_T dllBuffSize;

}DllInject, * PDllInject;