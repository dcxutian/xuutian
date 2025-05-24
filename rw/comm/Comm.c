#include "comm.h"
#include "comm7.h"
#include "comm10.h"
#include "../Search.h"

NTSTATUS RegisterComm(CommCallbackProc callback)
{
	RTL_OSVERSIONINFOEXW version = {0};
	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		return RegisterCommWin7(callback);
	}

	return RegisterCommWin10(callback);
}



VOID UnRegisterComm()
{
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		UnRegisterCommWin7();
		return;
	}

	UnRegisterCommWin10();
}