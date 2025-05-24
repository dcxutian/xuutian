#pragma once
#include <ntifs.h>

NTSTATUS InitObRegister();

VOID DestoryObRegister();


BOOLEAN SetProtectPid(HANDLE pid);