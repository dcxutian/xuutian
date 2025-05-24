#include "RW.h"
#include "ExportFunc.h"
#include <intrin.h>
#include "tools.h"

PVOID MdlMapMemory(PMDL * mdl, PVOID TargetAddress, SIZE_T size, MODE preMode)
{
	PMDL pMdl = IoAllocateMdl(TargetAddress, size, FALSE, FALSE, NULL);
	PVOID mapAddr = NULL;
	if (!pMdl)
	{
		return NULL;
	}

	BOOLEAN isLock = FALSE;
	__try 
	{
		MmProbeAndLockPages(pMdl, preMode, IoReadAccess);
		isLock = TRUE;
		//这个API 映射失败就会蓝屏
		//MmMapLockedPages
		mapAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except(1)
	{
	
		if (isLock)
		{
			MmUnlockPages(pMdl);
		}
		IoFreeMdl(pMdl);
		return NULL;
	}
	
	*mdl = pMdl;

	return mapAddr;

}

VOID MdlUnMapMemory(PMDL mdl, PVOID mapBase)
{
	__try
	{
		MmUnmapLockedPages(mapBase, mdl);

		MmUnlockPages(mdl);
	
		IoFreeMdl(mdl);
	}
	__except (1)
	{
		return;
	}
}

NTSTATUS ReadMemory1(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size)
{
	if ((ULONG64)TargetAddress >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) < (ULONG64)TargetAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (Buffer == NULL) return STATUS_INVALID_PARAMETER_3;
	
	PEPROCESS Process;
	KAPC_STATE kApcState = {0};
	
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != 0x103)
	{
		ObDereferenceObject(Process);
		return STATUS_INVALID_PARAMETER_1;
	}

	PVOID mem = ExAllocatePool(NonPagedPool, size);
	memset(mem, 0, size);

	KeStackAttachProcess(Process, &kApcState);
	status = STATUS_UNSUCCESSFUL;
	//64K
	if (MmIsAddressValid(TargetAddress) && MmIsAddressValid((PVOID)((ULONG64)TargetAddress + size)))
	{
		memcpy(mem, TargetAddress, size);
		status = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&kApcState);

	if (NT_SUCCESS(status))
	{
		memcpy(Buffer, mem, size);
	}

	ObDereferenceObject(Process);
	ExFreePool(mem);
	return status;
}

NTSTATUS ReadMemory4(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size)
{
	if ((ULONG64)TargetAddress >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) < (ULONG64)TargetAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (Buffer == NULL) return STATUS_INVALID_PARAMETER_3;

	PEPROCESS Process;
	

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != 0x103)
	{
		ObDereferenceObject(Process);
		return STATUS_INVALID_PARAMETER_1;
	}

	PVOID mem = ExAllocatePool(NonPagedPool, size);
	memset(mem, 0, size);

	
	status = STATUS_UNSUCCESSFUL;
	//64K
	ULONG64 newCr3 = *(PULONG64)((PUCHAR)Process + 0x28);

	ULONG64 oldCr3 = __readcr3();
	
	KeEnterCriticalRegion();
	
	_disable();
	
	__writecr3(newCr3);
	
	if (MmIsAddressValid(TargetAddress) && MmIsAddressValid((PVOID)((ULONG64)TargetAddress + size)))
	{
		memcpy(mem, TargetAddress, size);
		
		status = STATUS_SUCCESS;
	}

	_enable();

	__writecr3(oldCr3);

	KeLeaveCriticalRegion();

	if (NT_SUCCESS(status))
	{
		memcpy(Buffer, mem, size);
	}

	ObDereferenceObject(Process);
	ExFreePool(mem);
	return status;
}

NTSTATUS ReadMemory2(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size)
{
	if ((ULONG64)TargetAddress >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) < (ULONG64)TargetAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (Buffer == NULL) return STATUS_INVALID_PARAMETER_3;

	PEPROCESS Process;
	KAPC_STATE kApcState = { 0 };

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != 0x103)
	{
		ObDereferenceObject(Process);
		return STATUS_INVALID_PARAMETER_1;
	}

	SIZE_T pro = NULL;
	status = MmCopyVirtualMemory(Process, TargetAddress, IoGetCurrentProcess(), Buffer, size, UserMode, &pro);
	ObDereferenceObject(Process);
	return status;
}

NTSTATUS ReadMemory3(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size)
{
	if ((ULONG64)TargetAddress >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) < (ULONG64)TargetAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (Buffer == NULL) return STATUS_INVALID_PARAMETER_3;

	PEPROCESS Process;
	KAPC_STATE kApcState = { 0 };

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != 0x103)
	{
		ObDereferenceObject(Process);
		return STATUS_INVALID_PARAMETER_1;
	}

	PVOID mem = ExAllocatePool(NonPagedPool, size);
	memset(mem, 0, size);

	KeStackAttachProcess(Process, &kApcState);
	status = STATUS_UNSUCCESSFUL;
	//64K
	if (MmIsAddressValid(TargetAddress) && MmIsAddressValid((PVOID)((ULONG64)TargetAddress + size)))
	{
		PMDL mdl = NULL;
		PVOID map = MdlMapMemory(&mdl, TargetAddress, size, UserMode);
		if (map)
		{
			memcpy(mem, map, size);
			MdlUnMapMemory(mdl, map);
		}
		
		status = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&kApcState);

	if (NT_SUCCESS(status))
	{
		memcpy(Buffer, mem, size);
	}

	ObDereferenceObject(Process);
	ExFreePool(mem);
	return status;
}


NTSTATUS WriteMemory(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size)
{
	if ((ULONG64)TargetAddress >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) >= MmHighestUserAddress
		|| ((ULONG64)TargetAddress + size) < (ULONG64)TargetAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (Buffer == NULL) return STATUS_INVALID_PARAMETER_3;

	PEPROCESS Process;
	KAPC_STATE kApcState = { 0 };

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (PsGetProcessExitStatus(Process) != 0x103)
	{
		ObDereferenceObject(Process);
		return STATUS_INVALID_PARAMETER_1;
	}

	SIZE_T retSize = 0;
	status = MmCopyVirtualMemory(IoGetCurrentProcess(), Buffer, Process, TargetAddress, size, UserMode, &retSize);

	if (NT_SUCCESS(status))
	{
		ObDereferenceObject(Process);
		return status;
	}

	PEPROCESS SrcProcess = IoGetCurrentProcess();

	KeStackAttachProcess(Process, &kApcState);
	
	PVOID baseAddr = TargetAddress;
	SIZE_T tempSize = size;
	ULONG proAttr = 0;
	
	status = NtProtectVirtualMemory(NtCurrentProcess(),&baseAddr,&tempSize,PAGE_EXECUTE_READWRITE,&proAttr);
	if (NT_SUCCESS(status))
	{
		retSize = 0;
		status = MmCopyVirtualMemory(SrcProcess, Buffer, Process, TargetAddress, size, UserMode, &retSize);
		NtProtectVirtualMemory(NtCurrentProcess(), &baseAddr, &tempSize, proAttr, &proAttr);
	}
	KeUnstackDetachProcess(&kApcState);


	if (!NT_SUCCESS(status))
	{
		ULONG64 value = wpoff();
		retSize = 0;
		status = MmCopyVirtualMemory(IoGetCurrentProcess(), Buffer, Process, TargetAddress, size, UserMode, &retSize);
		wpon(value);
	}

	ObDereferenceObject(Process);

	return status;

}


//***************************************************************