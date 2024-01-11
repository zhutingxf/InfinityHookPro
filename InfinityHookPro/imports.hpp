#pragma once
#include "headers.hpp"
#include "defines.h"
#ifdef __cplusplus
extern "C"
{
#endif

	NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS  systemInformationClass,
		PVOID systemInformation,
		ULONG systemInformationLength,
		PULONG returnLength);

	NTSTATUS NTAPI NtTraceControl(
		ULONG FunctionCode,
		PVOID InBuffer,
		ULONG InBufferLen,
		PVOID OutBuffer,
		ULONG OutBufferLen,
		PULONG ReturnLength);

	ULONG NTAPI PsGetProcessSessionId(PEPROCESS Process);
	LONGLONG NTAPI RtlGetSystemTimePrecise();
#ifdef __cplusplus
}
#endif