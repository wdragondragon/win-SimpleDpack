#include <Windows.h>
#include "lzma\lzmalib.h"
/*
	dpack types and structures
	v0.2 by devseed
*/
#ifndef _DPACKTYPE_H
#define _DPACKTYPE_H
#define MAX_DPACKSECTNUM 16 // 最多可pack区段数量

typedef struct _DLZMA_HEADER
{
	DWORD RawDataSize;//原始数据尺寸(不含此头)
	DWORD DataSize;//压缩后的数据大小
	char Props[LZMA_PROPS_SIZE];//原始lzma的文件头
}DLZMA_HEADER,*PDLZMA_HEADER;//此处外围添加适用于dpack的lzma头

typedef struct _ORIGION_INDEX   //源程序被隐去的信息，此结构为明文表示，地址全是rva
{
#ifdef _WIN64
	ULONGLONG ImageBase;			//源程序基址
#else
	DWORD ImageBase;			//源程序基址
#endif
	DWORD OepRva;				//原程序rva入口
	DWORD ImportRva;			//导入表信息
	DWORD ImportSize;
}ORIGION_INDEX,*PORIGION_INDEX;

typedef struct _SECTION_INDEX //源信息与压缩变换后信息索引表是
{
	//假设不超过4g
	DWORD OrgRva;
	DWORD OrgSize;
	DWORD PackedRva;
	DWORD PackedSize;
}SECTION_INDEX, *PSECTION_INDEX;

typedef struct _DPACK_HDADER//DPACK变换头
{
	DWORD DpackOepRva;								//壳的入口（放第一个元素方便初始化）
	ORIGION_INDEX OrgIndex;
	WORD SectionNum;									//变换的区段数，最多MAX_DPACKSECTNUM区段
	SECTION_INDEX SectionIndex[MAX_DPACKSECTNUM];		//变换区段索引, 以全0结尾
	PVOID Extra;									//其他信息，方便之后拓展
}DPACK_HDADER,*PDPACK_HDADER;
#endif