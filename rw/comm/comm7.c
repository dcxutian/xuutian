#include "comm7.h"
#include "../Search.h"

CommCallbackProc gCommCallbackWin7 = NULL;


//----------------------------------------WIN7----------------------------
typedef NTSTATUS(*FileCallBack)(HANDLE FileHandle, PVOID info, PVOID un1, PVOID un2);

FileCallBack oldExpDisQueryAttributeInformationFunc = NULL;
FileCallBack oldExpDisSetAttributeInformationFunc = NULL;

PULONG64 gWin7CallbackVar = NULL;



typedef struct _RegisterCallback
{
	FileCallBack QueryFileCallback;
	FileCallBack SetFileCallBack;

}RegisterCallback, *PRegisterCallback;


typedef NTSTATUS(*ExRegisterAttributeInformationCallbackProc)(PRegisterCallback callbacks);

NTSTATUS QueryFileCallBack(HANDLE FileHandle, PVOID info, PVOID un1, PVOID un2)
{
	//KdPrintEx((77,0,"QueryFileCallBack\r\n"));
	if (MmIsAddressValid(info))
	{
		
		PCommPackage package = (PCommPackage)info;
		if (package->Id == 0x12345678)
		{
			package->retStatus = gCommCallbackWin7(package);

		}
		else
		{
			if (oldExpDisQueryAttributeInformationFunc)
			{
				return oldExpDisQueryAttributeInformationFunc(FileHandle, info, un1, un2);
			}
		}
	}

	
	return STATUS_SUCCESS;
}

NTSTATUS SetFileCallBack(HANDLE FileHandle, PVOID info,PVOID un1,PVOID un2)
{
	//KdPrintEx((77, 0, "SetFileCallBack\r\n"));
	if (MmIsAddressValid(info))
	{
		
		PCommPackage package = (PCommPackage)info;
		if (package->Id == 0x12345678)
		{
			package->retStatus = gCommCallbackWin7(package);
			
		}
		else 
		{
			if (oldExpDisSetAttributeInformationFunc)
			{
				return oldExpDisSetAttributeInformationFunc(FileHandle, info, un1, un2);
			}
		}

	}
	
	return STATUS_SUCCESS;
}

NTSTATUS RegisterCommWin7(CommCallbackProc callback)
{
	UNICODE_STRING unName = {0};
	RtlInitUnicodeString(&unName, L"ExRegisterAttributeInformationCallback");
	PUCHAR pFunc = MmGetSystemRoutineAddress(&unName);

	ULONG64 offset = *(PLONG)(pFunc + 0xd + 3);
	PULONG64 ExpDisQueryAttributeInformation = (PULONG64)((pFunc + 0xd + 7) + offset);

	oldExpDisQueryAttributeInformationFunc = (FileCallBack)ExpDisQueryAttributeInformation[0];
	oldExpDisSetAttributeInformationFunc = (FileCallBack)ExpDisQueryAttributeInformation[1];

	ExpDisQueryAttributeInformation[0] = 0;
	ExpDisQueryAttributeInformation[1] = 0;
	
	RegisterCallback rcb = {0};
	rcb.SetFileCallBack = SetFileCallBack;
	rcb.QueryFileCallback = QueryFileCallBack;

	ExRegisterAttributeInformationCallbackProc callFunc = (ExRegisterAttributeInformationCallbackProc)pFunc;

	NTSTATUS status = callFunc(&rcb);
	if (NT_SUCCESS(status))
	{
		gCommCallbackWin7 = callback;
		gWin7CallbackVar = ExpDisQueryAttributeInformation;
	}
	
	
	return status;
}

VOID UnRegisterCommWin7()
{
	if (gWin7CallbackVar)
	{
		gWin7CallbackVar[0] = oldExpDisQueryAttributeInformationFunc;
		gWin7CallbackVar[1] = oldExpDisSetAttributeInformationFunc;
	}

}

//----------------------------------------WIN7--END--------------------------
