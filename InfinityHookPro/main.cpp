#include "hook.hpp"
#include "imports.hpp"


NtCreateFilePtr g_NtCreateFile = 0;
NtTraceControlPtr g_NtTraceControl = 0;


NTSTATUS
NTAPI
FakeNtTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) return g_NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
        if (ExGetPreviousMode() == KernelMode) return g_NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
        if (PsGetProcessSessionId(IoGetCurrentProcess()) == 0) return g_NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
	if (FunctionCode == EtwpStopTrace)
	{
		GUID guidCkclSession = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
		CKCL_TRACE_PROPERTIES* pProperty = (CKCL_TRACE_PROPERTIES*)InBuffer;
		if (pProperty)
		{
			if (pProperty->Wnode.Guid == guidCkclSession)
			{
				DbgPrintEx(0, 0, "[%s] Deny Stop Circular Kernel Context Logger \n", __FUNCTION__);
				return STATUS_ACCESS_DENIED;
			}
		}
	}
	return g_NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
}

NTSTATUS FakeNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	// NtCreateFile 的调用方必须在 IRQL = PASSIVE_LEVEL且 启用了特殊内核 APC 的情况下运行
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (ExGetPreviousMode() == KernelMode) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (PsGetProcessSessionId(IoGetCurrentProcess()) == 0) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		wchar_t* name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t), '123');
		if (name)
		{
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			if (wcsstr(name, L"test.txt") && !wcsstr(name, L".ini"))
			{
				DbgPrintEx(0, 0, "Deny Access File: %ws \n", name);
				ExFreePool(name);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePool(name);
		}
	}

	return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress)
{
	// https://hfiref0x.github.io/
	UNREFERENCED_PARAMETER(nCallIndex);
	if (pSsdtAddress)
	{
		if (*pSsdtAddress == g_NtCreateFile) *pSsdtAddress = FakeNtCreateFile;
		if (*pSsdtAddress == g_NtTraceControl) *pSsdtAddress = FakeNtTraceControl;
	}
	
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	KHook::Stop();

	// 这里需要注意,确保系统的执行点已经不再当前驱动里面了
	// 比如当前驱动卸载掉了,但是你挂钩的MyNtCreateFile还在执行for操作,当然蓝屏啊
	// 这里的休眠10秒手段可以直接改进

	for (ULONG i = 10; i > 0; i--)
	{
		DbgPrintEx(0, 0, "[%s] Countdown : %d \n", __FUNCTION__, i);
                LARGE_INTEGER integer{ 0 };
                integer.QuadPart = -1000;
                integer.QuadPart *= 10000;
                KeDelayExecutionThread(KernelMode, FALSE, &integer);
	}
	DbgPrintEx(0, 0, "[%s] Completed! \n", __FUNCTION__);
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING registe)
{
	UNREFERENCED_PARAMETER(registe);

	driver->DriverUnload = DriverUnload;

	UNICODE_STRING str;
	WCHAR name[256]{ L"NtCreateFile" };
	RtlInitUnicodeString(&str, name);
	g_NtCreateFile = (NtCreateFilePtr)MmGetSystemRoutineAddress(&str);
        WCHAR name1[256]{ L"NtTraceControl" };
        RtlInitUnicodeString(&str, name1);
	g_NtTraceControl = (NtTraceControlPtr)MmGetSystemRoutineAddress(&str);
	// 初始化并挂钩
	return KHook::Initialize(InfinityCallback) && KHook::Start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}