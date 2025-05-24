#pragma once

#include <ntifs.h>

BOOLEAN RemoteCall(HANDLE pid, PVOID ShellCode, ULONG shellcodeSize);