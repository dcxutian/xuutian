#include "Module.h"

ULONG_PTR GetModuleX86(PEPROCESS Process,PPEB32 peb32,PUNICODE_STRING moudleName,PULONG_PTR sizeImage)
{
	SIZE_T retSize = 0;
	MmCopyVirtualMemory(Process, peb32, Process, peb32, 0x1, UserMode, &retSize);
	PPEB_LDR_DATA32 pebldr = UlongToPtr(peb32->Ldr);

	PLIST_ENTRY32 pList32  = (PLIST_ENTRY32)&pebldr->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY32 plistNext = (PLDR_DATA_TABLE_ENTRY32)UlongToPtr(pList32->Flink);
	
	ULONG_PTR module = 0;

	while (pList32 != plistNext)
	{

		PWCH baseDllName = plistNext->BaseDllName.Buffer;

		UNICODE_STRING uBaseName = {0};
		RtlInitUnicodeString(&uBaseName, baseDllName);

		if (RtlCompareUnicodeString(&uBaseName, moudleName, TRUE) == 0)
		{
			DbgPrintEx(77, 0, "[hotge]:imageBase = %llx,sizeofimage = %llx,%wZ\r\n", plistNext->DllBase, plistNext->SizeOfImage, &uBaseName);
			module = plistNext->DllBase;
			if (sizeImage) *sizeImage = plistNext->SizeOfImage;
			break;
		}


		plistNext = (PLDR_DATA_TABLE_ENTRY32)UlongToPtr(plistNext->InLoadOrderLinks.Flink);
	}

	return module;
}

ULONG_PTR GetModuleX64(PEPROCESS Process, PPEB peb, PUNICODE_STRING moudleName, PULONG_PTR sizeImage)
{
	SIZE_T retSize = 0;
	MmCopyVirtualMemory(Process, peb, Process, peb, 0x1, UserMode, &retSize);
	PPEB_LDR_DATA pebldr = peb->Ldr;

	PLIST_ENTRY pList = (PLIST_ENTRY)&pebldr->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY plistNext = (PLDR_DATA_TABLE_ENTRY)(pList->Flink);

	ULONG_PTR module = 0;
	
	while (pList != plistNext)
	{
		if (RtlCompareUnicodeString(&plistNext->BaseDllName, moudleName, TRUE) == 0)
		{
			DbgPrintEx(77, 0, "[hotge]:imageBase = %llx,sizeofimage = %llx,%wZ\r\n", plistNext->DllBase, plistNext->SizeOfImage, &plistNext->BaseDllName);
			module = plistNext->DllBase;
			if (sizeImage) *sizeImage = plistNext->SizeOfImage;
			break;
		}


		plistNext = (PLDR_DATA_TABLE_ENTRY)plistNext->InLoadOrderLinks.Flink;
	}

	return module;
}

ULONG_PTR GetModuleR3(HANDLE pid, char *moduleName, PULONG_PTR sizeImage)
{
	if (!moduleName) return 0;

	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = {0};
	ULONG_PTR moudule = 0;

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	STRING aModuleName = {0};
	RtlInitAnsiString(&aModuleName, moduleName);

	UNICODE_STRING uModuleName = {0};
	status = RtlAnsiStringToUnicodeString(&uModuleName, &aModuleName, TRUE);

	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	
	_wcsupr(uModuleName.Buffer);

	

	KeStackAttachProcess(Process, &kApcState);

	PPEB peb = PsGetProcessPeb(Process);

	PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(Process);



	if (peb32)
	{
		moudule = GetModuleX86(Process, peb32, &uModuleName, sizeImage);
	}
	else
	{
		moudule = GetModuleX64(Process, peb, &uModuleName, sizeImage);
	}


	KeUnstackDetachProcess(&kApcState);

	RtlFreeUnicodeString(&uModuleName);

	return moudule;
}

NTSTATUS QueryMemory(HANDLE pid, ULONG64 BaseAddress, PMyMEMORY_BASIC_INFORMATION pInformation)
{

	if (pInformation == NULL) return STATUS_UNSUCCESSFUL;

	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };

	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	

	PMEMORY_BASIC_INFORMATION pBaseInformation = (PMEMORY_BASIC_INFORMATION)ExAllocatePool(NonPagedPool, sizeof(MEMORY_BASIC_INFORMATION));

	memset(pBaseInformation, 0, sizeof(MEMORY_BASIC_INFORMATION));

	KeStackAttachProcess(Process, &kApcState);
	
	

	SIZE_T retLen = 0;
	status = ZwQueryVirtualMemory(NtCurrentProcess(), BaseAddress, MemoryBasicInformation, pBaseInformation, sizeof(MEMORY_BASIC_INFORMATION),&retLen);

	KeUnstackDetachProcess(&kApcState);

	if (NT_SUCCESS(status))
	{
		pInformation->AllocationBase = pBaseInformation->AllocationBase;
		pInformation->AllocationProtect = pBaseInformation->AllocationProtect;
		pInformation->BaseAddress = pBaseInformation->BaseAddress;
		pInformation->Protect = pBaseInformation->Protect;
		pInformation->RegionSize = pBaseInformation->RegionSize;
		pInformation->State = pBaseInformation->State;
		pInformation->Type = pBaseInformation->Type;

		
	}

	ObDereferenceObject(Process);
	ExFreePool(pBaseInformation);

	return status;
}


// 从内核模式读取用户模式内存
NTSTATUS ReadUserMemory(HANDLE hProcess, PVOID UserAddress, PVOID Buffer, SIZE_T Size) {
    SIZE_T BytesRead = 0;
    return MmCopyVirtualMemory(
        hProcess, UserAddress,
        PsGetCurrentProcess(), Buffer,
        Size, KernelMode, &BytesRead
    );
}

// 解析导出表并获取 LoadLibraryA 地址
PVOID GetLoadLibraryAAddress(HANDLE pid, ULONG_PTR ModuleBase,char* func) {

    PEPROCESS hProcess = NULL;
    NTSTATUS  status = PsLookupProcessByProcessId(pid, &hProcess);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    IMAGE_DOS_HEADER DosHeader = { 0 };
    IMAGE_NT_HEADERS NtHeaders = { 0 };
    IMAGE_EXPORT_DIRECTORY ExportDir = { 0 };

    // 1. 读取 DOS 头
    if (!NT_SUCCESS(ReadUserMemory(hProcess, (PVOID)ModuleBase, &DosHeader, sizeof(DosHeader)))) {
        DbgPrint("Failed to read DOS header\n");
        return NULL;
    }

    // 2. 检查 DOS 签名 ("MZ")
    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrint("Invalid DOS signature\n");
        return NULL;
    }

    // 3. 读取 NT 头
    ULONG_PTR NtHeadersAddr = ModuleBase + DosHeader.e_lfanew;
    if (!NT_SUCCESS(ReadUserMemory(hProcess, (PVOID)NtHeadersAddr, &NtHeaders, sizeof(NtHeaders)))) {
        DbgPrint("Failed to read NT headers\n");
        return NULL;
    }

    // 4. 检查 PE 签名 ("PE\0\0")
    if (NtHeaders.Signature != IMAGE_NT_SIGNATURE) {
        DbgPrint("Invalid PE signature\n");
        return NULL;
    }

    // 5. 获取导出表 RVA 和大小
    ULONG ExportDirRva = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (ExportDirRva == 0 || ExportDirSize == 0) {
        DbgPrint("No export directory found\n");
        return NULL;
    }

    // 6. 读取导出表
    ULONG_PTR ExportDirAddr = ModuleBase + ExportDirRva;
    if (!NT_SUCCESS(ReadUserMemory(hProcess, (PVOID)ExportDirAddr, &ExportDir, sizeof(ExportDir)))) {
        DbgPrint("Failed to read export directory\n");
        return NULL;
    }

    // 7. 读取导出函数名数组、序号数组、函数地址数组
    LONG* FunctionNames = NULL;
    UINT16* Ordinals = NULL;
    LONG* Functions = NULL;

    FunctionNames = ExAllocatePool(PagedPool, ExportDir.NumberOfNames * sizeof(LONG));
    Ordinals = ExAllocatePool(PagedPool, ExportDir.NumberOfNames * sizeof(UINT16));
    Functions = ExAllocatePool(PagedPool, ExportDir.NumberOfFunctions * sizeof(LONG));

    if (!FunctionNames || !Ordinals || !Functions) {
        DbgPrint("Memory allocation failed\n");
        goto Cleanup;
    }

    // 读取函数名数组
    if (!NT_SUCCESS(ReadUserMemory(
        hProcess,
        (PVOID)(ModuleBase + ExportDir.AddressOfNames),
        FunctionNames,
        ExportDir.NumberOfNames * sizeof(LONG)
    ))) {
        DbgPrint("Failed to read function names\n");
        goto Cleanup;
    }

    // 读取序号数组
    if (!NT_SUCCESS(ReadUserMemory(
        hProcess,
        (PVOID)(ModuleBase + ExportDir.AddressOfNameOrdinals),
        Ordinals,
        ExportDir.NumberOfNames * sizeof(UINT16)
    ))) {
        DbgPrint("Failed to read ordinals\n");
        goto Cleanup;
    }

    // 读取函数地址数组
    if (!NT_SUCCESS(ReadUserMemory(
        hProcess,
        (PVOID)(ModuleBase + ExportDir.AddressOfFunctions),
        Functions,
        ExportDir.NumberOfFunctions * sizeof(LONG)
    ))) {
        DbgPrint("Failed to read function addresses\n");
        goto Cleanup;
    }

    // 8. 遍历所有导出函数，查找 "LoadLibraryA"
    for (LONG i = 0; i < ExportDir.NumberOfNames; i++) {
        CHAR FuncName[64] = { 0 };
        ULONG_PTR FuncNameAddr = ModuleBase + FunctionNames[i];

        // 读取函数名
        if (!NT_SUCCESS(ReadUserMemory(hProcess, (PVOID)FuncNameAddr, FuncName, sizeof(FuncName)))) {
            continue;
        }

        // 检查是否为 "LoadLibraryA"
        if (strcmp(FuncName, func) == 0) {
            UINT16 Ordinal = Ordinals[i];
            LONG FuncRva = Functions[Ordinal];
            PVOID FuncAddress = (PVOID)(ModuleBase + FuncRva);

            DbgPrint("Found LoadLibraryA at 0x%p\n", FuncAddress);

            // 释放内存并返回地址
            ExFreePool(FunctionNames);
            ExFreePool(Ordinals);
            ExFreePool(Functions);
            return FuncAddress;
        }
    }

Cleanup:
    if (FunctionNames) ExFreePool(FunctionNames);
    if (Ordinals) ExFreePool(Ordinals);
    if (Functions) ExFreePool(Functions);
    return NULL;
}





//*******
NTSTATUS SafeGetProcessFunctionTable(HANDLE ProcessId) {
    PEPROCESS Process = NULL;

    KAPC_STATE kApcState = { 0 };
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 检查进程是否正在退出
    if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {
        ObDereferenceObject(Process);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    KeStackAttachProcess(Process, &kApcState);
    PPEB pPeb = PsGetProcessPeb(Process);
    if (!pPeb) {
        ObDereferenceObject(Process);
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        if (!pPeb->Ldr) {
            ObDereferenceObject(Process);
            return STATUS_UNSUCCESSFUL;
        }

        PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY pListEntry = pListHead->Flink;

        while (pListEntry != pListHead) {
            PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
                pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            PVOID pImageBase = pEntry->DllBase;
            if (!pImageBase) {
                pListEntry = pListEntry->Flink;
                continue;
            }

            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                pListEntry = pListEntry->Flink;
                continue;
            }

            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pImageBase + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                pListEntry = pListEntry->Flink;
                continue;
            }

            PIMAGE_DATA_DIRECTORY pExceptionDir =
                &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

            if (pExceptionDir->VirtualAddress && pExceptionDir->Size) {
                DbgPrint("@86[Safe] Module: %wZ\n", &pEntry->FullDllName);
                DbgPrint("  @86Exception Directory at 0x%p, Size: 0x%X\n",
                    (PVOID)((ULONG_PTR)pImageBase + pExceptionDir->VirtualAddress),
                    pExceptionDir->Size);
            }

            pListEntry = pListEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("@86Exception 0x%X occurred while reading process memory\n",
            GetExceptionCode());
        KeUnstackDetachProcess(&kApcState);
        ObDereferenceObject(Process);
        return GetExceptionCode();
       
    }
    KeUnstackDetachProcess(&kApcState);
    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}