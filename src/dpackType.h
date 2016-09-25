#include <Windows.h>
#include "lzma\lzmalib.h"
/*
	dpack types and structures
*/
#ifndef _DPACKTYPE_H
#define _DPACKTYPE_H
#define MAX_DPACKSECTNUM 16//最多的pack区段数量
typedef struct _DLZMA_HEADER
{
	DWORD dwRawDataSize;//原始数据尺寸(不含此头)
	DWORD dwDataSize;//压缩后的数据大小
	char outProps[LZMA_PROPS_SIZE];//原始lzma的文件头
}DLZMA_HEADER,*PDLZMA_HEADER;//此处外围添加适用于dpack的lzma头

typedef struct _ORIGION_INDEX32   //源程序被隐去的信息，此结构为明文表示，地址全是rva
{
	DWORD dwImageBase;			//源程序基址
	DWORD dwOepRva;				//原程序rva入口
	DWORD dwExportRva;		    //导出表表信息
	DWORD dwExportSize;
	DWORD dwImportRva;			//导入表信息
	DWORD dwImportSize;
	DWORD dwResourceRva;		//资源目录
	DWORD dwResourceSize;
	DWORD dwRelocRva;			//重定位表信息
	DWORD dwRelocSize;
	DWORD dwTlsRva;			//tls信息
	DWORD dwTlsSize;
}ORIGION_INDEX32,*PORIGION_INDEX32;

typedef struct _TRANS_INDEX //源信息与变换后信息索引表是
{
	//假设不超过4g
	DWORD dwOrigion_rva;
	DWORD dwOrigion_size;
	DWORD dwTrans_rva;
	DWORD dwTrans_size;
}TRANS_INDEX,*PTRANS_INDEX;

typedef struct _DPACK_DETAIL32//DPACK变换详细信息
{
	PVOID extre;
}DPACK_DETAIL32,*PDPACK_DETAIL32;

typedef struct _DPACK_OUT32//dll输出的信息
{
	PVOID extre;
}DPACK_OUT32,*PDPACK_OUT32;

typedef struct _DPACK_HDADER32//DPACK变换头
{
	DWORD dpackOepVa;								//壳的入口（放第一个元素方便初始化）
	ORIGION_INDEX32 origin_index;					//原始pe的一些信息
	WORD trans_num;									//变换的区段数，最多MAX_DPACKSECTNUM区段
	TRANS_INDEX trans_index[MAX_DPACKSECTNUM];		//变换区段索引
	DPACK_DETAIL32 detail;							//pack的详细信息
	DPACK_OUT32 out;								//用于输入dll的一些信息
	PVOID extre;									//其他信息，方便之后拓展
}DPACK_HDADER32,*PDPACK_HDADER32;
#endif