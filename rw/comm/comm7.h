#pragma once
#include <ntifs.h>
#include "commStruct.h"


NTSTATUS RegisterCommWin7(CommCallbackProc callback);

VOID UnRegisterCommWin7();