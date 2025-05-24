#include "comm10.h"
#include "../Search.h"

CommCallbackProc gCommCallbackWin10 = NULL;

typedef NTSTATUS(NTAPI * NewKdEnumerateDebuggingDevicesProc)(PVOID un1, PVOID un2, PVOID un3);

NewKdEnumerateDebuggingDevicesProc gOldNewKdEnumerateDebuggingDevicesFunc = NULL;
PULONG64 gWin10HookPoint = NULL;

NTSTATUS NewKdEnumerateDebuggingDevices(PVOID info, PVOID un2, PVOID un3)
{
	KdPrintEx((77, 0, "NewKdEnumerateDebuggingDevices\r\n"));
	
	if (MmIsAddressValid(info))
	{	
		PCommPackage package = (PCommPackage)info;
		if (package->Id == 0x12345678)
		{
			package->retStatus = gCommCallbackWin10(package);

		}
		else
		{
			if (gOldNewKdEnumerateDebuggingDevicesFunc)
			{
				return gOldNewKdEnumerateDebuggingDevicesFunc(info, un2, un3);
			}
		}

	}

	return STATUS_SUCCESS;
}

NTSTATUS RegisterCommWin10(CommCallbackProc callback)
{
	
	//NtConvertBetweenAuxiliaryCounterAndPerformanceCounter					 
	PUCHAR func = searchCode("ntoskrnl.exe", "PAGE", "488B05****75*488B05****E8", 0);
	if (func)
	{
		ULONG64 offset = *(PLONG)(func + 3);
		PULONG64 RepFunc = (PULONG64)((func +  7) + offset);

		gWin10HookPoint = RepFunc;

		gOldNewKdEnumerateDebuggingDevicesFunc = RepFunc[0];
		
		RepFunc[0] = NewKdEnumerateDebuggingDevices;

		gCommCallbackWin10 = callback;
	}


	

	return STATUS_SUCCESS;
}




VOID UnRegisterCommWin10()
{
	if (gOldNewKdEnumerateDebuggingDevicesFunc)
	{
		gWin10HookPoint[0] = gOldNewKdEnumerateDebuggingDevicesFunc;
	}

	gOldNewKdEnumerateDebuggingDevicesFunc = NULL;
}
