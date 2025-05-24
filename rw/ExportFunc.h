#pragma once
#include <ntifs.h>

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

EXTERN_C void  * NTAPI PsGetProcessWow64Process(PEPROCESS Process);

EXTERN_C PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);

EXTERN_C void * NTAPI PsGetThreadTeb(PETHREAD Thread);

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
);

 NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID *FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

