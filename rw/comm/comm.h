#pragma once
#include <ntifs.h>
#include "commStruct.h"




NTSTATUS RegisterComm(CommCallbackProc callback);

VOID UnRegisterComm();