#pragma once
#include <ntifs.h>

//直接memcpy读写 附加
NTSTATUS ReadMemory1(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size);


// MmCopyVirtualMemory
NTSTATUS ReadMemory2(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size);


//MDL
NTSTATUS ReadMemory3(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size);

//直接切CR3
NTSTATUS ReadMemory4(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size);



NTSTATUS WriteMemory(HANDLE pid, PVOID TargetAddress, PVOID Buffer, SIZE_T size);