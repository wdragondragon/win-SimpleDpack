#include <Windows.h>
#include "DpackType.h"
extern "C"
{
#include "dunpackCode.h"
}
#ifndef _SIMPLEDPACKSHELL32_H
#define _SIMPLEDPACKSHELL32_H
#define DPACK_API __declspec(dllexport)

extern "C" DPACK_API DPACK_HDADER32 g_stcShellHDADER32;//导出的结构
void unpackAll();		
void fixOrigionIat();	//修复原来的iat
#endif