#pragma once
#include <ntifs.h>
#include "ExportFunc.h"
#include "Module.h"




NTSTATUS InjectX64(HANDLE pid, char *shellcode, SIZE_T shellcodeSize);

NTSTATUS InjectX86(HANDLE pid, char *shellcode, SIZE_T shellcodeSize);


