#pragma once
#include "headers.hpp"
#include "defines.h"
namespace KHook
{
	// 初始化数据
	bool Initialize(InfinityCallbackPtr ssdtCallBack);

	// 开始拦截函数调用
	bool Start();

	// 结束拦截函数调用
	bool Stop();
}