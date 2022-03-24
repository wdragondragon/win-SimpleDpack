/*
	simpledpackshell v0.5,
	The shellcode to be append to exe file to unpack
	designed by devseed,
	https://github.com/YuriSizuku/SimpleDpack/
*/

#include <Windows.h>
#define DPACK_API __declspec(dllexport)
#define DLZMANOPACK
#ifndef _SIMPLEDPACKSHELL_H
#define _SIMPLEDPACKSHELL_H
extern "C" {
    #include "dpackType.h"
	void BeforeUnpack(); // 解压前的操作，比如说加密解密相关
	void AfterUnpack(); // 解压后操作
	void JmpOrgOep();// 跳转到源程序
}
void MallocAll(PVOID arg); // 预分配内存
void UnpackAll(PVOID arg); // 解压所有区段
void LoadOrigionIat(PVOID arg);	// 加载原来的iat
#endif