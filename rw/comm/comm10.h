#pragma once
#include <ntifs.h>
#include "commStruct.h"

NTSTATUS RegisterCommWin10(CommCallbackProc callback);

VOID UnRegisterCommWin10();