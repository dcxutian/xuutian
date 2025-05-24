#include <ntifs.h>
#include "Module.h"
#include "comm\comm.h"
#include "comm\commStruct.h"
#include "RW.h"
#include "ProtectedProcess.h"
#include "FarCall.h"
#include "Inject.h"

NTSTATUS NTAPI DispatchComm(PCommPackage package)
{
	PVOID data = package->Data;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//DbgPrintEx(77, 0, "[db]:%llx,%llx\r\n", package->Id, package->cmd);
	switch (package->cmd)
	{
	case CMD_TEST:
		status = STATUS_SUCCESS;
		break;
	
	case CMD_GET_MODULE:
	{
		
		PModuleInfo info = (PModuleInfo)data;
		if (info)
		{
			ULONG64 imageSize = 0;
			info->Module = GetModuleR3(info->pid, info->moduleName,&imageSize);
			info->ModuleSize = imageSize;
			status = STATUS_SUCCESS;
		}

		
	}
		break;

	case CMD_READ_MEMORY:
	{
		PReadWriteInfo info = (PReadWriteInfo)data;
		if (info)
		{
			status = ReadMemory2(info->pid, info->BaseAddress, info->Buffer, info->size);
		}
	}
	break;


	case CMD_WRITE_MEMORY:
	{
		PReadWriteInfo info = (PReadWriteInfo)data;
		if (info)
		{
			status = WriteMemory(info->pid, info->BaseAddress, info->Buffer, info->size);
		}
	}
	break;

	case CMD_QUERY_MEMORY:
	{
		PQueryMemoryInfo info = (PQueryMemoryInfo)data;
		if (info)
		{
			status = QueryMemory(info->pid, info->BaseAddress, &info->memoryInfo);
		}
	}
	break;


	case CMD_PROTECT_PROCESS:
	{
		PProtectInfo info = (PProtectInfo)data;
		if (info)
		{
			SetProtectPid(info->pid);
			status = STATUS_SUCCESS;
		}
	}
	break;

	case CMD_REMOTE_CALL:
	{
		PRemoteCallInfo info = (PRemoteCallInfo)data;
		if (info)
		{
			RemoteCall(info->pid, info->shellcode, info->shellcodeSize);
			status = STATUS_SUCCESS;
		}
	}
	break;

	case CMD_Dll_Inject_X86:
	{
		PDllInject info = (PDllInject)data;
		if (info)
		{
			status = InjectX86(info->pid, info->dllBuff, info->dllBuffSize);
		}
	}
	break;

	case CMD_Dll_Inject_X64:
	{
		PDllInject info = (PDllInject)data;
		if (info)
		{
			status = InjectX64(info->pid, info->dllBuff, info->dllBuffSize);
		}
	}
	break;
	default:
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	
	return status;
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

	DbgPrint("@86 DriverUnload ---> %s\n", "DriverUnload");
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
	UnRegisterComm();
	DestoryObRegister();
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	NTSTATUS status = STATUS_SUCCESS;
	
	

	RegisterComm(DispatchComm);

	DbgPrint("@86  DriverEntry ---> %s\n","START");

	InitObRegister();


	
	


	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}