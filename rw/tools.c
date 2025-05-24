#include "tools.h"
#include <intrin.h>

NTSTATUS NTAPI NtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{
	
	typedef NTSTATUS(NTAPI *ZwProtectVirtualMemoryProc)(
		__in HANDLE ProcessHandle,
		__inout PVOID *BaseAddress,
		__inout PSIZE_T RegionSize,
		__in ULONG NewProtect,
		__out PULONG OldProtect
		);

	static ZwProtectVirtualMemoryProc ZwProtectVirtualMemoryFunc = NULL;
	if (!ZwProtectVirtualMemoryFunc)
	{
		UNICODE_STRING uNname = { 0 };
		RtlInitUnicodeString(&uNname, L"ZwIsProcessInJob");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&uNname);

		if (func)
		{
			func += 20;
			for (int i = 0; i < 0x100; i++)
			{
				if (func[i] == 0x48 && func[i+1] == 0x8b && func[i+2] == 0xc4)
				{
					ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryProc)(func + i);
					break;
				}
			}
		}
		
	
	}

	if (ZwProtectVirtualMemoryFunc)
	{
		return ZwProtectVirtualMemoryFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	}

	return STATUS_NOT_IMPLEMENTED;
}

ULONG64 wpoff()
{
	_disable();
	ULONG64 mcr0 = __readcr0();
	__writecr0(mcr0 & (~0x10000));

	return mcr0;
}

VOID wpon(ULONG64 mcr0)
{
	__writecr0(mcr0);
	_enable();
}

VOID KernelSleep(ULONG64 ms,BOOLEAN alert)
{
	LARGE_INTEGER inTime;
	inTime.QuadPart = ms * -10000;
	KeDelayExecutionThread(KernelMode, alert, &inTime);
}