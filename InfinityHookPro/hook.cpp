#pragma warning(disable : 4201 4819 4311 4302)
#include "hook.hpp"
#include "utils.hpp"

namespace KHook
{
        InfinityCallbackPtr m_InfinityCallback = nullptr;
        unsigned long m_BuildNumber = 0;
        void* m_SystemCallTable = nullptr;
        bool m_DetectThreadStatus = true;
        void* m_EtwpDebuggerData = nullptr;
        void* m_CkclWmiLoggerContext = nullptr;
        void** m_EtwpDebuggerDataSilo = nullptr;
        void** m_GetCpuClock = nullptr;
        PETHREAD m_DetectThreadObject = NULL;
        PLONGLONG m_QpcPointer = NULL;
        PMDL m_QpcMdl = NULL;
        unsigned long long m_OriginalGetCpuClock = 0;
        unsigned long long m_HvlpReferenceTscPage = 0;
        unsigned long long m_HvlGetQpcBias = 0;
        unsigned long long m_HvlpGetReferenceTimeUsingTscPage = 0;
        unsigned long long m_HalpPerformanceCounter = 0;
        unsigned long long m_HalpOriginalPerformanceCounter = 0;
        unsigned long long m_HalpOriginalPerformanceCounterCopy = 0;
        unsigned long* m_HalpPerformanceCounterType = 0;
        unsigned char m_VmHalpPerformanceCounterType = 0;
        unsigned long m_OriginalHalpPerformanceCounterType = 0;
        unsigned long long m_OriginalHvlpGetReferenceTimeUsingTscPage = 0;
        typedef __int64 (*FHvlGetQpcBias)();
        FHvlGetQpcBias m_OriginalHvlGetQpcBias = nullptr;
        CLIENT_ID m_ClientId = { 0 };

        // 修改跟踪设置
        NTSTATUS EventTraceControl(ETWP_TRACE_TYPE nType)
        {
                const unsigned long nTag = 'VMON';

                // 申请结构体空间
                CKCL_TRACE_PROPERTIES* pProperty = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, nTag);
                if (!pProperty)
                {
                        DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
                        return STATUS_MEMORY_NOT_ALLOCATED;
                }

                // 申请保存名称的空间
                wchar_t* szProviderName = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(wchar_t), nTag);
                if (!szProviderName)
                {
                        DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
                        ExFreePoolWithTag(pProperty, nTag);
                        return STATUS_MEMORY_NOT_ALLOCATED;
                }

                // 清空内存
                RtlZeroMemory(pProperty, PAGE_SIZE);
                RtlZeroMemory(szProviderName, 256 * sizeof(wchar_t));

                // 名称赋值
                RtlCopyMemory(szProviderName, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
                RtlInitUnicodeString(&pProperty->ProviderName, (const wchar_t*)szProviderName);

                // 唯一标识符
                GUID guidCkclSession = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

                // 结构体填充
                pProperty->Wnode.BufferSize = PAGE_SIZE;
                pProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                pProperty->Wnode.Guid = guidCkclSession;
                pProperty->Wnode.ClientContext = 3;
                pProperty->BufferSize = sizeof(unsigned long);
                pProperty->MinimumBuffers = 2;
                pProperty->MaximumBuffers = 2;
                pProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

                // 执行操作
                unsigned long nLength = 0;
                if (nType == ETWP_TRACE_TYPE::EtwpUpdateTrace) pProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
                NTSTATUS ntStatus = NtTraceControl(nType, pProperty, PAGE_SIZE, pProperty, PAGE_SIZE, &nLength);

                // 释放内存空间
                ExFreePoolWithTag(szProviderName, nTag);
                ExFreePoolWithTag(pProperty, nTag);

                return ntStatus;
        }

        // 我们的替换函数,针对的是从Win7到Win10 1909的系统
        unsigned long long SelfGetCpuClock()
        {
                // 放过内核模式的调用
                if (ExGetPreviousMode() == KernelMode) return __rdtsc();

                // 拿到当前线程
                PKTHREAD pCurrentThread = (PKTHREAD)__readgsqword(0x188);

                // 不同版本不同偏移
                unsigned int nCallIndex = 0;
                if (m_BuildNumber <= 7601) nCallIndex = *(unsigned int*)((unsigned long long)pCurrentThread + 0x1f8);
                else nCallIndex = *(unsigned int*)((unsigned long long)pCurrentThread + 0x80);

                // 拿到当前栈底和栈顶
                void** pStackMax = (void**)__readgsqword(0x1a8);
                void** pStackFrame = (void**)_AddressOfReturnAddress();

                // 开始查找当前栈中的ssdt调用
                for (void** pStackCurrent = pStackMax; pStackCurrent > pStackFrame; --pStackCurrent)
                {
                        /*
                                Win11 23606 以前 栈中ssdt调用特征, 分别是
                                mov r9d, 0F33h
                                mov [rsp+48h+var_20], 501802h
                                Win11 23606 及以后 栈中ssdt调用特征, 分别是
                                mov r9d, 0F33h
                                mov[rsp + 58h + var_30], 601802h
                        */
#define INFINITYHOOK_MAGIC_501802 ((unsigned long)0x501802) //Win11 23606 以前系统特征码
#define INFINITYHOOK_MAGIC_601802 ((unsigned long)0x601802) //Win11 23606 及以后系统的特征码
#define INFINITYHOOK_MAGIC_F33 ((unsigned short)0xF33)


                        // 第一个特征值检查
                        unsigned long* pValue1 = (unsigned long*)pStackCurrent;
                        if ((*pValue1 != INFINITYHOOK_MAGIC_501802) &&
                                (*pValue1 != INFINITYHOOK_MAGIC_601802))
                        {
                                continue;
                        }

                        // 这里为什么减?配合寻找第二个特征值啊
                        --pStackCurrent;

                        // 第二个特征值检查
                        unsigned short* pValue2 = (unsigned short*)pStackCurrent;
                        if (*pValue2 != INFINITYHOOK_MAGIC_F33)
                        {
                                continue;
                        }

                        // 特征值匹配成功,再倒过来查找
                        for (; pStackCurrent < pStackMax; ++pStackCurrent)
                        {
                                // 检查是否在ssdt表内
                                unsigned long long* pllValue = (unsigned long long*)pStackCurrent;
                                if (!(PAGE_ALIGN(*pllValue) >= m_SystemCallTable &&
                                        PAGE_ALIGN(*pllValue) < (void*)((unsigned long long)m_SystemCallTable + (PAGE_SIZE * 2))))
                                        continue;

                                // 现在已经确定是ssdt函数调用了
                                // 这里是找到KiSystemServiceExit
                                void** pSystemCallFunction = &pStackCurrent[9];

                                // 调用回调函数
                                if (m_InfinityCallback) m_InfinityCallback(nCallIndex, pSystemCallFunction);

                                // 跳出循环
                                break;
                        }

                        // 跳出循环
                        break;
                }

                // 调用原函数
                return __rdtsc();
        }

        // 我们的替换函数,针对的是Win 1919往上的系统
        EXTERN_C __int64 FakeHvlGetQpcBias()
        {
                // 我们的过滤函数
                SelfGetCpuClock();

                // 这里是真正HvlGetQpcBias做的事情
                 //物理机上 HvlpReferenceTscPage指针值为空
                if (*((unsigned long long*)m_HvlpReferenceTscPage) != 0)
                {
                        return *((unsigned long long*)(*((unsigned long long*)m_HvlpReferenceTscPage)) + 3);
                }
                return 0;
        }

        // 检测例程
        void DetectThreadRoutine(void*)
        {
                while (m_DetectThreadStatus)
                {
                        // 线程常用休眠
                        KUtils::Sleep(1000);
                        // GetCpuClock还是一个函数指针
                        if (m_BuildNumber <= 18363)
                        {

                                if (MmIsAddressValid(m_GetCpuClock) && MmIsAddressValid(*m_GetCpuClock))
                                {
                                        // 值不一样,必须重新挂钩
                                        if (SelfGetCpuClock != *m_GetCpuClock)
                                        {
                                                DbgPrintEx(0, 0, "[%s] fix 0x%p 0x%p \n", __FUNCTION__, m_GetCpuClock, MmIsAddressValid(m_GetCpuClock) ? *m_GetCpuClock : 0);
                                                if (Initialize(m_InfinityCallback)) Start();
                                        }
                                }
                                else Initialize(m_InfinityCallback); // GetCpuClock无效后要重新获取
                        }
                        LARGE_INTEGER li = KeQueryPerformanceCounter(NULL);
                        //DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                }
                PsTerminateSystemThread(STATUS_SUCCESS);
        }
#define HALP_PERFORMANCE_COUNTER_TYPE_OFFSET (0xE4)  //HalpPerformanceCounter类型值偏移，该值在物理机器中为5，虚拟机中 Win11 22621 以上为7, 以下为 8
#define HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET (0xC0) //HalpPerformanceCounter基本速度倍率地址  虚拟机中为值为 0x989680=10000000， 物理机中为约2000000000
#define HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE  (0x5) //物理机中HalpPerformanceCounter的类型
#define HALP_PERFORMANCE_COUNTER_BASE_RATE (10000000i64) //基本速度


        bool Initialize(InfinityCallbackPtr pCallback)
        {
                if (!m_DetectThreadStatus) return false;

                // 回调函数指针检查
                DbgPrintEx(0, 0, "[%s] ssdt call back ptr is 0x%p \n", __FUNCTION__, pCallback);
                if (!MmIsAddressValid(pCallback)) return false;
                else m_InfinityCallback = pCallback;

                // 先尝试挂钩
                if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
                {
                        // 无法开启CKCL
                        if (!NT_SUCCESS(EventTraceControl(EtwpStartTrace)))
                        {
                                DbgPrintEx(0, 0, "[%s] start ckcl fail \n", __FUNCTION__);
                                return false;
                        }

                        // 再次尝试挂钩
                        if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
                        {
                                DbgPrintEx(0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__);
                                return false;
                        }
                }

                // 获取系统版本号
                m_BuildNumber = KUtils::GetSystemBuildNumber();
                DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, m_BuildNumber);
                if (!m_BuildNumber) return false;

                // 获取系统基址
                unsigned long long ntoskrnl = KUtils::GetModuleAddress("ntoskrnl.exe", nullptr);
                DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);
                if (!ntoskrnl) return false;

                // 这里不同系统不同位置
                // https://github.com/FiYHer/InfinityHookPro/issues/17  win10 21h2.2130 安装 KB5018410 补丁后需要使用新的特征码 
                unsigned long long EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
                if (!EtwpDebuggerData) EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
                if (!EtwpDebuggerData) EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
                DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
                if (!EtwpDebuggerData) return false;
                m_EtwpDebuggerData = (void*)EtwpDebuggerData;

                // 这里暂时不知道怎么定位,偏移0x10在全部系统都一样
                m_EtwpDebuggerDataSilo = *(void***)((unsigned long long)m_EtwpDebuggerData + 0x10);
                DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, m_EtwpDebuggerDataSilo);
                if (!m_EtwpDebuggerDataSilo) return false;

                // 这里也不知道怎么定位,偏移0x2在全部系统都哦一样
                m_CkclWmiLoggerContext = m_EtwpDebuggerDataSilo[0x2];
                DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, m_CkclWmiLoggerContext);
                if (!m_CkclWmiLoggerContext) return false;

                /*  Win7系统测试,m_GetCpuClock该值会改变几次,先阶段使用线程检测后修复
                *   靠,Win11的偏移变成了0x18,看漏的害我调试这么久  -_-
                *   这里总结一下,Win7和Win11都是偏移0x18,其它的是0x28
                */
                if (m_BuildNumber <= 7601 || m_BuildNumber >= 22000) m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x18); // Win7版本以及更旧, Win11也是
                else m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x28); // Win8 -> Win10全系统
                if (!MmIsAddressValid(m_GetCpuClock)) return false;
                DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p \n", __FUNCTION__, *m_GetCpuClock);

                // 拿到ssdt指针
                m_SystemCallTable = PAGE_ALIGN(KUtils::GetSyscallEntry(ntoskrnl));
                DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, m_SystemCallTable);
                if (!m_SystemCallTable) return false;

                if (m_BuildNumber > 18363) // 即版本1909
                {
                        /* HvlGetQpcBias函数内部需要用到这个结构
                        *   所以我们手动定位这个结构
                        */
                        // 特征码为 Win10 18363 至 Win11 22631全平台通用
                        unsigned long long addressHvlpReferenceTscPage = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
                                "xxx????xxx?xxx????xxx");
                        if (!addressHvlpReferenceTscPage)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlpReferenceTscPage Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(addressHvlpReferenceTscPage) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHvlpReferenceTscPage) + 3));
                        DbgPrintEx(0, 0, "[%s] HvlpReferenceTscPage is 0x%llX \n", __FUNCTION__, m_HvlpReferenceTscPage);
                        if (!m_HvlpReferenceTscPage) return false;
                        //-----------------------------------HvlpReferenceTscPage的原始值----------------------------
                        //-----------------------------虚拟机------------------物理机-----------------------
                        //Win10  20H2                        有                                  空
                        //Win10  21H1                        有                                  空
                        //Win10  21H2                        有                                  空
                        //Win10  22H2                        有                                  空
                        //Win11  22000                       有                                  空
                        //Win11  22621                       有                                  空
                        //Win11  22631                       有                                  空
                        DbgPrintEx(0, 0, "[%s] HvlpReferenceTscPage Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HvlpReferenceTscPage));
                        //if (*reinterpret_cast<unsigned long long*>(m_HvlpReferenceTscPage) == 0) return false; 

                        /* 这里我们查找到HvlGetQpcBias的指针
                        *   详细介绍可以看https://www.freebuf.com/articles/system/278857.html
                        */
                        //在函数 HalpTimerQueryHostPerformanceCounter 中
                        //__int64 __fastcall HalpTimerQueryHostPerformanceCounter(_QWORD * a1)
                        //{
                        //        __int64 v2; // rbx

                        //        if (!HalpPerformanceCounter
                        //                || *(_DWORD*)(HalpPerformanceCounter + 0xE4) != 7
                        //                || !HvlGetQpcBiasPtr
                        //                || !HvlGetReferenceTimeUsingTscPagePtr)
                        //        {
                        //                return 0xC00000BB;
                        //        }
                        //        v2 = HvlGetReferenceTimeUsingTscPagePtr(0i64);
                        //        *a1 = HvlGetQpcBiasPtr() + v2;
                        //        return 0i64;
                        //}
                        unsigned long long addressHvlGetQpcBias = 0;
                        //HalpTimerQueryHostPerformanceCounter中查找 HvlGetQpcBias    物理机 虚拟机 HvlGetQpcBias 值都为0
                        addressHvlGetQpcBias = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74", // Win10 22H2以前 以及 Win11 22621以前
                                "xxx????xxxx?xxx?????x");
                        if (!addressHvlGetQpcBias)
                        {
                                //该特征码全都有，但上个特征码在Win10 22H2 以及 Win11 22621以上没有，再搜索这个时就已经是 Win10 22H2 以及 Win11 22621以上版本
                                addressHvlGetQpcBias = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
                                        "xxx????x????xxxxxx");
                        }
                        if (!addressHvlGetQpcBias)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlGetQpcBias Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(addressHvlGetQpcBias) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHvlGetQpcBias) + 3));
                        DbgPrintEx(0, 0, "[%s] HvlGetQpcBias Is 0x%llX \n", __FUNCTION__, m_HvlGetQpcBias);
                        if (!m_HvlGetQpcBias) return false;
                        //-----------------------------------HvlGetQpcBias的原始值----------------------------
                        //-----------------------------虚拟机------------------物理机-----------------------
                        //Win10  20H2                        空                                  空
                        //Win10  21H1                        空                                  空
                        //Win10  21H2                        空                                  空
                        //Win10  22H2                        空                                  空
                        //Win11  22000                       空                                  空
                        //Win11  22621                       空                                  空             
                        //Win11  22631                       空                                  空
                        DbgPrintEx(0, 0, "[%s] HvlGetQpcBias Value Is 0x%llX \n", __FUNCTION__, *(unsigned long long*)m_HvlGetQpcBias);



                        //HalpTimerQueryHostPerformanceCounter中查找 HvlGetReferenceTimeUsingTscPagePtr 
                        //物理机 HvlGetReferenceTimeUsingTscPagePtr 值为0
                        unsigned long long addressHvlpGetReferenceTimeUsingTscPage = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x33\xc9\xe8\x00\x00\x00\x00\x48\x8b\xd8",  //Win10 22H2 和 Win11 22621及以上
                                "xxx????xxxx?xxx????xxx");
                        if (!addressHvlpGetReferenceTimeUsingTscPage)
                        {
                                //该特征码全平台都有，但上个特征码在 Win10 22H2以前， 以及 Win11 22621 以前没有，再搜索这个时就已经是 Win10 21H1、21H2、 以及 Win11 22000版本了
                                addressHvlpGetReferenceTimeUsingTscPage = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x03\xd8",
                                        "xxx????x????xxx");
                        }
                        if (!addressHvlpGetReferenceTimeUsingTscPage)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlpGetReferenceTimeUsingTscPage Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlpGetReferenceTimeUsingTscPage = (unsigned long long)
                                ((char*)(addressHvlpGetReferenceTimeUsingTscPage)+7 +
                                        *(int*)((char*)(addressHvlpGetReferenceTimeUsingTscPage)+3));
                        DbgPrintEx(0, 0, "[%s] HvlGetReferenceTimeUsingTscPage Is 0x%llX \n", __FUNCTION__, m_HvlpGetReferenceTimeUsingTscPage);
                        if (!m_HvlpGetReferenceTimeUsingTscPage) return false;
                        //-----------------------HvlpGetReferenceTimeUsingTscPage的原始值----------------
                        //--------------------------------------虚拟机---------------------------------------------------物理机-----------------------
                        //Win10  20H2        nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        //Win10  21H1        nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        //Win10  21H2        nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        //Win10  22H2        nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        //Win11  22000       nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        //Win11  22621       nt!HvlGetReferenceTimeUsingTscPage                                                      空                         
                        //Win11  22631       nt!HvlGetReferenceTimeUsingTscPage                                                      空
                        DbgPrintEx(0, 0, "[%s] HvlGetReferenceTimeUsingTscPage Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HvlpGetReferenceTimeUsingTscPage));


                        //HalpTimerQueryHostPerformanceCounter中搜索HalpPerformanceCounter
                        unsigned long long  addressHalpPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\xf9\x48\x85\xc0\x74\x00\x83\xb8", //特征码全平台一样
                                "xxx????xxxxxxx?xx");
                        if (!addressHalpPerformanceCounter)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HalpPerformanceCounter Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HalpPerformanceCounter = reinterpret_cast<unsigned long long>
                                (reinterpret_cast<char*>(addressHalpPerformanceCounter) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHalpPerformanceCounter) + 3));
                        DbgPrintEx(0, 0, "[%s] HalpPerformanceCounter Is 0x%llX \n", __FUNCTION__, m_HalpPerformanceCounter);
                        if (!m_HalpPerformanceCounter) return false;
                        DbgPrintEx(0, 0, "[%s] HalpPerformanceCounter Value is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HalpPerformanceCounter));


                        //在 KiUpdateTime中搜索HalpOriginalPerformanceCounter，Win10 21H1 至 Win11 22631 通用
                        unsigned long long  addressHalpOriginalPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x3b\x00\x0f\x85\x00\x00\x00\x00\xA0",
                                "xxx????xx?xx????x");
                        if (!addressHalpOriginalPerformanceCounter)
                        {
                                //Win11 23606 之后,在 KeQueryPerformanceCounter 中搜索HalpOriginalPerformanceCounter
                                addressHalpOriginalPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x0d\x00\x00\x00\x00\x4c\x00\x00\x00\x00\x48\x3b\xf1",
                                        "xxx????x????xxx");
                                if (!addressHalpOriginalPerformanceCounter)
                                {
                                        DbgPrintEx(0, 0, "[%s] Find HalpOriginalPerformanceCounter Failed! \n", __FUNCTION__);
                                        return false;
                                }
                        }

                        m_HalpOriginalPerformanceCounter = reinterpret_cast<unsigned long long>
                                (reinterpret_cast<char*>(addressHalpOriginalPerformanceCounter) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHalpOriginalPerformanceCounter) + 3));
                        DbgPrintEx(0, 0, "[%s] HalpOriginalPerformanceCounter Is 0x%llX \n", __FUNCTION__, m_HalpOriginalPerformanceCounter);
                        if (!m_HalpOriginalPerformanceCounter) return false;
                        DbgPrintEx(0, 0, "[%s] HalpOriginalPerformanceCounter Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HalpOriginalPerformanceCounter));

                        //HalpPerformanceCounter中类型的指针，后面进行修改时使用
                        m_HalpPerformanceCounterType = (ULONG*)((ULONG_PTR)(*(PVOID*)m_HalpPerformanceCounter) + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET);
                        if (!m_HalpPerformanceCounterType)
                        {
                                DbgPrintEx(0, 0, "[%s] m_HalpPerformanceCounterType Is Null! \n", __FUNCTION__);
                                return false;
                        }
                        //判断在物理机上时才进行后边的操作
                        if (*m_HalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE)
                        {
                                //搜索HalpTimerQueryHostPerformanceCounter中判断的Type值，其实也可以直接判断系统版本
                                //参考HalpTimerQueryHostPerformanceCounter中 *(_DWORD *)(HalpPerformanceCounter + 0xE4) != 7 ,
                                                                //Win11 22000 及以下值为8  22621 以上为7
                                //利用前边搜索的 addressHalpPerformanceCounter,以下注释为Win11 22621 HalpTimerQueryHostPerformanceCounter 的 IDA逆向代码
                                //.text : 0000000140520A1A 48 8B 05 8F 36 74 00                              mov     rax, cs : HalpPerformanceCounter
                                //.text : 0000000140520A21 48 8B F9                                                   mov     rdi, rcx
                                //.text : 0000000140520A24 48 85 C0                                                   test    rax, rax
                                //.text : 0000000140520A27 74 3F                                                         jz      short loc_140520A68
                                //.text : 0000000140520A29 83 B8 E4 00 00 00 07                                cmp     dword ptr[rax + 0E4h], 7
                                m_VmHalpPerformanceCounterType = *(reinterpret_cast<char*>(addressHalpPerformanceCounter) + 21);
                                DbgPrintEx(0, 0, "[%s] HalpPerformanceCounterType In Virtual Machine Value is 0x%x \n", __FUNCTION__, m_VmHalpPerformanceCounterType);

                                //分配一个同HalpPerformanceCounter一样的空间，用来替换HalpOriginalPerformanceCounter，
                                //替换的数据中Type为 5, 倍数为基准的 10000000, 
                                //ntoskrnl中的原逻辑为 HalpOriginalPerformanceCounter = HalpPerformanceCounter
                                m_HalpOriginalPerformanceCounterCopy = (ULONGLONG)ExAllocatePoolWithTag(NonPagedPool, 0xFF, 'freP');
                                if (!m_HalpOriginalPerformanceCounterCopy)
                                {
                                        DbgPrintEx(0, 0, "[%s] Allocate m_HalpOriginalPerformanceCounterReplace Failed!\n", __FUNCTION__);
                                        return false;
                                }
                                RtlZeroMemory((PVOID)m_HalpOriginalPerformanceCounterCopy, 0xFF);
                                //设置基本速度，
                                *(PULONGLONG)(m_HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET) = HALP_PERFORMANCE_COUNTER_BASE_RATE;
                                *(PULONG)(m_HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET) = HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE;
                                DbgPrintEx(0, 0, "[%s] m_HalpOriginalPerformanceCounterCopy：0x%llX \n", __FUNCTION__, m_HalpOriginalPerformanceCounterCopy);

                                // KUSER_SHARED_DATA的QpcBias字段，在从系统从睡眠状态恢复正常状态后停止时，系统时间修正时使用
                                PLONGLONG pQpcPointer = (PLONGLONG)0xFFFFF780000003B8;
                                m_QpcMdl = IoAllocateMdl(pQpcPointer, 8, false, false, NULL);
                                if (!m_QpcMdl)
                                {
                                        DbgPrintEx(0, 0, "[%s] m_QpcMdl IoAllocateMdl Failed!\n", __FUNCTION__);
                                        return false;
                                }
                                MmBuildMdlForNonPagedPool(m_QpcMdl);
                                m_QpcPointer = (PLONGLONG)MmMapLockedPagesSpecifyCache(m_QpcMdl, KernelMode, MmWriteCombined, NULL, false, NormalPagePriority);
                                if (!m_QpcPointer)
                                {
                                        DbgPrintEx(0, 0, "[%s] m_QpcPointer MmMapLockedPagesSpecifyCache Failed!\n", __FUNCTION__);
                                        return false;
                                }
                        }

                }

                return true;
        }

        ULONG64 FakeGetReferenceTimeUsingTscPage()
        {
                return __rdtsc();
        }

        bool Start()
        {
                if (!m_InfinityCallback) return false;

                // 无效指针
                if (!MmIsAddressValid(m_GetCpuClock))
                {
                        DbgPrintEx(0, 0, "[%s] get cpu clock vaild \n", __FUNCTION__);
                        return false;
                }

                /* 这里我们区分一下系统版本
                *   从Win7到Win10 1909,m_GetCpuClock是一个函数,往后的版本是一个数值了
                *   大于3抛异常
                *   等于3用rdtsc
                *   等于2用off_140C00A30
                *   等于1用KeQueryPerformanceCounter
                *   等于0用RtlGetSystemTimePrecise
                *   我们的做法参考网址https://www.freebuf.com/articles/system/278857.html
                *   我们这里在2身上做文章
                */
                // 保存GetCpuClock原始值,退出时好恢复
                m_OriginalGetCpuClock = (unsigned long long)(*m_GetCpuClock);
                if (m_BuildNumber <= 18363)
                {
                        // 直接修改函数指针
                        DbgPrintEx(0, 0, "[%s] GetCpuClock Is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
                        *m_GetCpuClock = SelfGetCpuClock;
                        DbgPrintEx(0, 0, "[%s] Update GetCpuClock Is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
                }
                else
                {

                        /* 这里我们设置为2, 这样子才能调用off_140C00A30函数
                        *   其实该指针就是HalpTimerQueryHostPerformanceCounter函数
                        *   该函数里面又有两个函数指针,第一个就是HvlGetQpcBias,就是我们的目标
                        */
                        *m_GetCpuClock = (void*)2;
                        DbgPrintEx(0, 0, "[%s] Update GetCpuClock Is %p \n", __FUNCTION__, *m_GetCpuClock);

                        // 保存旧HvlGetQpcBias地址,方便后面清理的时候复原环境
                        m_OriginalHvlGetQpcBias = (HvlGetQpcBiasPtr)(*((unsigned long long*)m_HvlGetQpcBias));

                        //物理机HvlpGetReferenceTimeUsingTscPage为空，在虚拟机上指向HvlGetReferenceTimeUsingTscPage函数，
                        //故在值为空时进行修改，但改为HvlGetReferenceTimeUsingTscPage后蓝屏，尝试改为NtYieldExecution但未导出，改ZwYieldExecution后导致重入错误，
                        //经实验改为一个没有参数的函数,函数返回 __rdtsc
                        if (m_HvlpGetReferenceTimeUsingTscPage)
                        {
                                //不能使用原来的HvlGetReferenceTimeUsingTscPage，在 HvlpGetReferenceTimeUsingTscPage 值为空时，函数里的有数据结构未初始化
                                m_OriginalHvlpGetReferenceTimeUsingTscPage = *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage);
                                if (m_OriginalHvlpGetReferenceTimeUsingTscPage == 0) //只在HvlpGetReferenceTimeUsingTscPage值为空时才设置，其它保持原始不变
                                {
                                        *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage) = (ULONGLONG)FakeGetReferenceTimeUsingTscPage;
                                        DbgPrintEx(0, 0, "[%s] Update HvlpGetReferenceTimeUsingTscPage Value : %p \n", __FUNCTION__, (PVOID)FakeGetReferenceTimeUsingTscPage);
                                }

                        }


                        //这个是性能计数器的类型 在虚拟机上为 7或者8 物理机上为 5 参见 HalpTimerSelectRoles 中的 HalpTimerFindIdealPerformanceCounterSource
                        m_OriginalHalpPerformanceCounterType = *m_HalpPerformanceCounterType;
                        DbgPrintEx(0, 0, "[%s] Original HalpPerformanceCounterType Value : %d\n", __FUNCTION__, m_OriginalHalpPerformanceCounterType);
                        if (*m_HalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE) //只在物理机的情况下进行修改
                        {
                                //更改 HalpOriginalPerformanceCounter，原值为 m_HalpPerformanceCounter的值 
                                *(unsigned long long*)m_HalpOriginalPerformanceCounter = m_HalpOriginalPerformanceCounterCopy;
                                DbgPrintEx(0, 0, "[%s] Update HalpOriginalPerformanceCounter Value: %llX\n", __FUNCTION__, m_HalpOriginalPerformanceCounterCopy);
                                LARGE_INTEGER li = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                                //需要把性能计数器类型改为虚拟机环境下的判断值，调整逻辑 参见 HalpTimerSelectRoles 中的 HalpTimerFindIdealPerformanceCounterSource
                                *m_HalpPerformanceCounterType = m_VmHalpPerformanceCounterType;  //改为虚拟机环境中的类型，7或者8
                                DbgPrintEx(0, 0, "[%s] Update HalpPerformanceCounterType Value : %d\n", __FUNCTION__, m_VmHalpPerformanceCounterType);
                                li = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                        }


                        // 设置钩子
                        *((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)FakeHvlGetQpcBias;
                        DbgPrintEx(0, 0, "[%s] Update HvlGetQpcBias Value is %p \n", __FUNCTION__, FakeHvlGetQpcBias);

                }

                static bool s_IsThreadCreated = false;
                if (!s_IsThreadCreated)
                {
                        s_IsThreadCreated = true;
                        OBJECT_ATTRIBUTES att{ 0 };
                        HANDLE hThread = NULL;
                        InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
                        NTSTATUS ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &att, 0, &m_ClientId, DetectThreadRoutine, 0);
                        if (!NT_SUCCESS(ntStatus))
                        {
                                DbgPrintEx(0, 0, "[%s] Create Detect Thread Failed! \n", __FUNCTION__);
                        }
                        else
                        {
                                ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&m_DetectThreadObject, NULL);
                                DbgPrintEx(0, 0, "[%s] Detect Routine Thread ID Is %d \n", __FUNCTION__, (int)m_ClientId.UniqueThread);
                                DbgPrintEx(0, 0, "[%s] Detect Routine Thread Object Is %p \n", __FUNCTION__, m_DetectThreadObject);
                        }

                }

                return true;
        }

        bool Stop()
        {
                // 停止检测线程
                m_DetectThreadStatus = false;

                bool bResult = NT_SUCCESS(EventTraceControl(EtwpStopTrace)) && NT_SUCCESS(EventTraceControl(EtwpStartTrace));
                DbgPrintEx(0, 0, "[%s] Enter... \n", __FUNCTION__);

                if (m_DetectThreadObject)
                {
                        DbgPrintEx(0, 0, "[%s] Wait For Detect Thread Termination \n", __FUNCTION__);
                        KeWaitForSingleObject(m_DetectThreadObject, Executive, KernelMode, false, NULL);
                        ObDereferenceObject(m_DetectThreadObject);
                        DbgPrintEx(0, 0, "[%s] Detect Thread Terminated \n", __FUNCTION__);
                }
                //m_GetCpuClock值还原要在线程停止之后，否则可能还原后又被线程里的逻辑改为我们的函数了
                *m_GetCpuClock = (void*)m_OriginalGetCpuClock;
                DbgPrintEx(0, 0, "[%s] Restore GetCpuClock is  %p \n", __FUNCTION__, *m_GetCpuClock);
                // Win10 1909以上系统需要恢复环境
                if (m_BuildNumber > 18363)
                {

                        if (m_HvlpGetReferenceTimeUsingTscPage)
                        {
                                //还原 HvlpGetReferenceTimeUsingTscPage的值为m_OriginalHvlpGetReferenceTimeUsingTscPage，也即 0
                                if (m_OriginalHvlpGetReferenceTimeUsingTscPage == 0)
                                {
                                        *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage) = m_OriginalHvlpGetReferenceTimeUsingTscPage;
                                        DbgPrintEx(0, 0, "[%s] Restore HvlpGetReferenceTimeUsingTscPage Value is  0x%llX \n", __FUNCTION__, m_OriginalHvlpGetReferenceTimeUsingTscPage);
                                }
                        }

                        //只在物理机上进行以下还原
                        if (m_OriginalHalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE)
                        {
                                LARGE_INTEGER liBegin = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count Before Restore %lld \n", __FUNCTION__, liBegin.QuadPart);
                                //还原 顺序保持下面的顺序
                                *m_HalpPerformanceCounterType = m_OriginalHalpPerformanceCounterType;
                                //不能还原m_HalpOriginalPerformanceCounter为原始的值 m_HalpPerformanceCounter, 
                                //而需要保留m_HalpOriginalPerformanceCounter为m_HalpOriginalPerformanceCounterCopy的值
                                //否则还原后计数器时间返回会比之前小很多导致死锁
                                //*(unsigned long long*)m_HalpOriginalPerformanceCounter = m_HalpPerformanceCounter;

                                LARGE_INTEGER liEndFix = KeQueryPerformanceCounter(NULL);
                                //修正睡眠之后恢复正常停止时时间错误导致系统假死问题
                                if (liEndFix.QuadPart - liBegin.QuadPart > HALP_PERFORMANCE_COUNTER_BASE_RATE)
                                {
                                        LONGLONG llQpcValue = *m_QpcPointer;
                                        llQpcValue -= liEndFix.QuadPart - liBegin.QuadPart;
                                        *m_QpcPointer = llQpcValue;
                                        DbgPrintEx(0, 0, "[%s] Fix Qpc Value :%llX\n", __FUNCTION__, llQpcValue);
                                }

                                LARGE_INTEGER liEnd = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Restore HalpPerformanceCounterType Value is  %ld \n", __FUNCTION__, m_OriginalHalpPerformanceCounterType);
                                DbgPrintEx(0, 0, "[%s] Tick Count After Restore %lld \n", __FUNCTION__, liEnd.QuadPart);
                                if (m_QpcMdl)
                                {
                                        DbgPrintEx(0, 0, "[%s] Free Qpc Mdl\n", __FUNCTION__);
                                        IoFreeMdl(m_QpcMdl);
                                        m_QpcMdl = NULL;
                                }
                        }
                        *((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)m_OriginalHvlGetQpcBias;
                        DbgPrintEx(0, 0, "[%s] Restore HvlGetQpcBias is %p \n", __FUNCTION__, m_OriginalHvlGetQpcBias);

                }

                if (bResult)
                {
                        DbgPrintEx(0, 0, "[%s] Stop Finished! \n", __FUNCTION__);
                }
                else
                {
                        DbgPrintEx(0, 0, "[%s] Stop Failed! \n", __FUNCTION__);
                }
                return bResult;
        }
}
