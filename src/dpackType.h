/*
	simpledpackshell v0.4 ,
	The shellcode type declear, such as DPACK_SHELL_INDEX 
	designed by devseed,
	https://github.com/YuriSizuku/SimpleDpack/
*/

#include <Windows.h>
#ifndef _DPACKPROC_H
#define _DPACKPROC_H
#define MAX_DPACKSECTNUM 16 // 最多可pack区段数量
#include "lzma\lzmalib.h"

typedef struct _DLZMA_HEADER
{
	size_t RawDataSize;//原始数据尺寸(不含此头)
	size_t DataSize;//压缩后的数据大小
	char LzmaProps[LZMA_PROPS_SIZE];//原始lzma的文件头
}DLZMA_HEADER, *PDLZMA_HEADER;//此处外围添加适用于dpack的lzma头

typedef struct _DPACK_ORGPE_INDEX   //源程序被隐去的信息，此结构为明文表示，地址全是rva
{
#ifdef _WIN64
	ULONGLONG ImageBase;			//源程序基址
#else
	DWORD ImageBase;			//源程序基址
#endif
	DWORD OepRva;				//原程序rva入口
	DWORD ImportRva;			//导入表信息
	DWORD ImportSize;
}DPACK_ORGPE_INDEX, * PDPACK_ORGPE_INDEX;

#define DPACK_SECTION_RAW 0
#define DPACK_SECTION_DLZMA 1

typedef struct _DPACK_SECTION_ENTRY //源信息与压缩变换后信息索引表是
{
	//假设不超过4g
	DWORD OrgRva; // OrgRva为0时则是不解压到原来区段
	DWORD OrgSize; 
	DWORD DpackRva;
	DWORD DpackSize; 
	DWORD Characteristics;
	DWORD DpackSectionType; // dpack区段类型
}DPACK_SECTION_ENTRY, * PDPACK_SECTION_ENTRY;

typedef struct _DPACK_SHELL_INDEX//DPACK变换头
{
	union 
	{
		PVOID DpackOepFunc;  // 初始化壳的入口函数（放第一个元素方便初始化）
		DWORD DpackOepRva;  // 加载shellcode后也许改成入口RVA
	};
	DPACK_ORGPE_INDEX OrgIndex;
	WORD SectionNum;									//变换的区段数，最多MAX_DPACKSECTNUM区段
	DPACK_SECTION_ENTRY SectionIndex[MAX_DPACKSECTNUM];		//变换区段索引, 以全0结尾
	PVOID Extra;									//其他信息，方便之后拓展
}DPACK_SHELL_INDEX, * PDPACK_SHELL_INDEX;

size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);
#endif