#pragma once
#include <ntifs.h>

NTSTATUS NTAPI NtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

ULONG64 wpoff();

VOID wpon(ULONG64 mcr0);

VOID KernelSleep(ULONG64 ms, BOOLEAN alert);