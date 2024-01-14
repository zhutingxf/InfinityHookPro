#pragma once
#include "headers.hpp"

/* 微软官方文档定义
*   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
*/
//typedef struct _WNODE_HEADER
//{
//        ULONG BufferSize;
//        ULONG ProviderId;
//        union {
//                ULONG64 HistoricalContext;
//                struct {
//                        ULONG Version;
//                        ULONG Linkage;
//                };
//        };
//        union {
//                HANDLE KernelHandle;
//                LARGE_INTEGER TimeStamp;
//        };
//        GUID Guid;
//        ULONG ClientContext;
//        ULONG Flags;
//} WNODE_HEADER, * PWNODE_HEADER;

/* 微软文档定义
*   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
*/
typedef struct _EVENT_TRACE_PROPERTIES
{
        WNODE_HEADER Wnode;
        ULONG BufferSize;
        ULONG MinimumBuffers;
        ULONG MaximumBuffers;
        ULONG MaximumFileSize;
        ULONG LogFileMode;
        ULONG FlushTimer;
        ULONG EnableFlags;
        union {
                LONG AgeLimit;
                LONG FlushThreshold;
        } DUMMYUNIONNAME;
        ULONG NumberOfBuffers;
        ULONG FreeBuffers;
        ULONG EventsLost;
        ULONG BuffersWritten;
        ULONG LogBuffersLost;
        ULONG RealTimeBuffersLost;
        HANDLE LoggerThreadId;
        ULONG LogFileNameOffset;
        ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

/*
*  这结构是大佬逆向出来的
*/
typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
        ULONG64 Unknown[3];
        UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

/*
*  操作类型
*/
typedef enum _ETWP_TRACE_TYPE
{
        EtwpStartTrace = 1,
        EtwpStopTrace = 2,
        EtwpQueryTrace = 3,
        EtwpUpdateTrace = 4,
        EtwpFlushTrace = 5
}ETWP_TRACE_TYPE;


typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemProcessorInformation = 1,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemPathInformation = 4,
        SystemProcessInformation = 5,
        SystemCallCountInformation = 6,
        SystemDeviceInformation = 7,
        SystemProcessorPerformanceInformation = 8,
        SystemFlagsInformation = 9,
        SystemCallTimeInformation = 10,
        SystemModuleInformation = 11,
        SystemLocksInformation = 12,
        SystemStackTraceInformation = 13,
        SystemPagedPoolInformation = 14,
        SystemNonPagedPoolInformation = 15,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17,
        SystemPageFileInformation = 18,
        SystemVdmInstemulInformation = 19,
        SystemVdmBopInformation = 20,
        SystemFileCacheInformation = 21,
        SystemPoolTagInformation = 22
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
        HANDLE  Section;
        PVOID  MappedBase;
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{ 
        ULONG_PTR ulModuleCount;
        SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef void(__fastcall* InfinityCallbackPtr)(unsigned long nCallIndex, PVOID* pCallAddress);
typedef __int64 (*HvlGetQpcBiasPtr)();
typedef NTSTATUS(*NtCreateFilePtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtTraceControlPtr)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef LONG_PTR(FASTCALL* ObfDereferenceObjectPtr)(PVOID);
typedef LONG_PTR(NTAPI* ObDereferenceObjectPtr)(PVOID);
//typedef struct _GLOBAL_INFORMATION
//{
//        bool DetectThreadTerminated;
//        CLIENT_ID ClientId;
//        InfinityCallbackPtr InfinityCallback;
//        unsigned long BuildNumber;
//        void* SystemCallTable;
//        void* EtwpDebuggerData;
//        void* CkclWmiLoggerContext;
//        void** EtwpDebuggerDataSilo;
//        void** GetCpuClock;
//        PETHREAD DetectThreadObject;
//        unsigned long long OriginalGetCpuClock;
//        unsigned long long HvlpReferenceTscPage;
//        unsigned long long HvlGetQpcBias;
//        unsigned long long HvlpGetReferenceTimeUsingTscPage;
//        unsigned long long HalpPerformanceCounter;
//        unsigned long long HalpOriginalPerformanceCounter;
//        unsigned long long HalpOriginalPerformanceCounterCopy;
//        unsigned long* HalpPerformanceCounterType;
//        unsigned char VmHalpPerformanceCounterType;
//        unsigned long OriginalHalpPerformanceCounterType;
//        unsigned long long OriginalHvlpGetReferenceTimeUsingTscPage;
//        HvlGetQpcBiasPtr  OriginalHvlGetQpcBias;
//}GLOBAL_INFORMATION;
