#pragma once
#include "imports.hpp"
#include "defines.h"
#include "hde/hde64.h"

namespace KUtils
{

	// 获取系统版本号
	unsigned long GetSystemBuildNumber()
	{
		unsigned long nNumber = 0;
		RTL_OSVERSIONINFOEXW info{ 0 };
		info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) nNumber = info.dwBuildNumber;
		return nNumber;
	}
	
	// 获取指定模块基址
	unsigned long long GetModuleAddress(const char* szName, unsigned long* nSize)
	{
		unsigned long long nResult = 0;

		unsigned long nLength = 0;
		ZwQuerySystemInformation(SystemModuleInformation, &nLength, 0, &nLength);
		if (!nLength) return nResult;

		const unsigned long nTag = 'VMON';
		PSYSTEM_MODULE_INFORMATION pSystemModules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, nLength, nTag);
		if (!pSystemModules) return nResult;

		NTSTATUS nStatus = ZwQuerySystemInformation(SystemModuleInformation, pSystemModules, nLength, 0);
		if (NT_SUCCESS(nStatus))
		{
			for (unsigned long long i = 0; i < pSystemModules->ulModuleCount; i++)
			{
				PSYSTEM_MODULE_INFORMATION_ENTRY pMod = &pSystemModules->Modules[i];
				if (strstr(pMod->ImageName, szName))
				{
					nResult = (unsigned long long)pMod->Base;
					if (nSize) *nSize = (unsigned long)pMod->Size;
					break;
				}
			}
		}

		ExFreePoolWithTag(pSystemModules, nTag);
		return nResult;
	}

	// 模式匹配
	bool PatternCheck(const char* pData, const char* szPattern, const char* szMask)
	{
		size_t nLen = strlen(szMask);

		for (size_t i = 0; i < nLen; i++)
		{
			if (pData[i] == szPattern[i] || szMask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	// 模式查找
	unsigned long long FindPattern(unsigned long long pAddress, unsigned long nSize, const char* szPattern, const char* szMask)
	{
		nSize -= (unsigned long)strlen(szMask);

		for (unsigned long i = 0; i < nSize; i++)
		{
			if (PatternCheck((const char*)pAddress + i, szPattern, szMask))
				return pAddress + i;
		}

		return 0;
	}

	// 查找映像模式
	unsigned long long FindPatternImage(unsigned long long pAddress, const char* szPattern, const char* szMask, const char* szSectionName = ".text")
	{
		PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pAddress;
		if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 pImageNtHeader = (PIMAGE_NT_HEADERS64)(pAddress + pImageDosHeader->e_lfanew);
		if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);
		for (unsigned short i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &pImageSectionHeader[i];

			if (strstr((const char*)p->Name, szSectionName))
			{
				unsigned long long nResult = FindPattern(pAddress + p->VirtualAddress, p->Misc.VirtualSize, szPattern, szMask);
				if (nResult) return nResult;
			} 
		}

		return 0;
	}

	// 获取映像地址
	unsigned long long GetImageSectionAddress(unsigned long long pAddress, const char* szSectionName, unsigned long* nSize)
	{
		PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pAddress;
		if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 pImageNtHeader = (PIMAGE_NT_HEADERS64)(pAddress + pImageDosHeader->e_lfanew);
		if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);
		for (unsigned short i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &pImageSectionHeader[i];

			if (strstr((const char*)p->Name, szSectionName))
			{
				if (nSize) *nSize = p->SizeOfRawData;
				return (unsigned long long)p + p->VirtualAddress;
			}
		}

		return 0;
	}

	// 获取SSDT表地址
	void* GetSyscallEntry(unsigned long long ntoskrnl)
	{
		if (!ntoskrnl) return nullptr;

		/*
		2018年的内核页表隔离补丁 https://bbs.pediy.com/thread-223805.htm
		没有补丁的话就是KiSystemCall64
		*/
#define IA32_LSTAR_MSR 0xC0000082
		void* pSyscallEntry = (void*)__readmsr(IA32_LSTAR_MSR);

		// 没有补丁过,直接返回KiSystemCall64就行
		unsigned long nSectionSize = 0;
		unsigned long long pKVASCODE = GetImageSectionAddress(ntoskrnl, "KVASCODE", &nSectionSize);
		if (!pKVASCODE) return pSyscallEntry;

		// KiSystemCall64还是在区域内,也是直接返回
		if (!(pSyscallEntry >= (void*)pKVASCODE && pSyscallEntry < (void*)(pKVASCODE + nSectionSize))) return pSyscallEntry;

		// 来到这一步那就是KiSystemCall64Shadow,代表打补丁了
		hde64s hdeInfo{ 0 };
		for (char* pKiSystemServiceUser = (char*)pSyscallEntry; ; pKiSystemServiceUser += hdeInfo.len)
		{
			// 反汇编
			if (!hde64_disasm(pKiSystemServiceUser, &hdeInfo)) break;

			// 我们要查找jmp
#define OPCODE_JMP_NEAR 0xE9
			if (hdeInfo.opcode != OPCODE_JMP_NEAR) continue;

			// 忽略在KVASCODE节区内的jmp指令
			void* pPossibleSyscallEntry = (void*)((long long)pKiSystemServiceUser + (int)hdeInfo.len + (int)hdeInfo.imm.imm32);
			if (pPossibleSyscallEntry >= (void*)pKVASCODE && pPossibleSyscallEntry < (void*)((unsigned long long)pKVASCODE + nSectionSize)) continue;

			// 发现KiSystemServiceUser
			pSyscallEntry = pPossibleSyscallEntry;
			break;
		}

		return pSyscallEntry;
	}

	// 休眠函数
	void Sleep(long msec)
	{
		LARGE_INTEGER liDelay{ 0 };

		// 这里的负数表示的是相对时间，正数拒说表示绝对时间，我没试出效果。单位是100nm,此处乘以10000是让单位变为s,很多代码都是乘以10,即传入的单位是ms;
		liDelay.QuadPart = -10000;
		liDelay.QuadPart *= msec;
		KeDelayExecutionThread(KernelMode, FALSE, &liDelay);
	}
}