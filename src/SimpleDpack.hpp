/*
	SimpleDpack v0.5 ,
	to pack the pe32/pe64 pe file
	designed by devseed,
	https://github.com/YuriSizuku/SimpleDpack/
*/

#include <Windows.h>
#include "PEedit.hpp"
extern "C" // c++中引用c必须要这样
{
    #include <Psapi.h>	
	#include "dpackType.h"
}
#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H
/*
	pack the pe file class
*/

typedef struct _DPACK_TMPBUF_ENTRY
{
	LPBYTE PackedBuf;
	DWORD  DpackSize;
	DWORD  OrgRva;//若此项为0，则添加到最后一个区段，不压缩
	DWORD  OrgMemSize;
	DWORD  Characteristics;
}DPACK_TMPBUF_ENTRY, * PDPACK_TMPBUF_ENTRY; // 最后一个放shellcode

class CSimpleDpack
{
public:
	static LPBYTE dlzmaPack(LPBYTE pSrcBuf, size_t srcSize, 
		size_t* pDstSize, double maxmul = 2.0); // 加壳lzma压缩算法
	static LPBYTE dlzmaUnpack(LPBYTE pSrcBuf, size_t srcSize); // lzma解压算法

private:
	char m_strFilePath[MAX_PATH];

protected:
	CPEedit m_packpe; // 需要加壳的exe pe结构
	CPEedit m_shellpe; // 壳的pe结构
	PDPACK_SHELL_INDEX m_pShellIndex; // dll中的导出结构
	HMODULE m_hShell; // 壳dll的句柄

	WORD m_dpackSectNum; 
	DPACK_TMPBUF_ENTRY m_dpackTmpbuf[MAX_DPACKSECTNUM]; // 加壳区段索引
	bool m_packSectMap[MAX_DPACKSECTNUM]; // 区段是否被压缩map

	WORD initDpackTmpbuf();//返回原来dpackTmpBuf数量
	WORD addDpackTmpbufEntry (LPBYTE packBuf, DWORD packBufSize,
		DWORD srcRva = 0, DWORD OrgMemSize = 0, DWORD Characteristics= 0xE0000000);//增加dpack索引
	DWORD packSection(int type=DPACK_SECTION_DLZMA);	//pack各区段
	
	DWORD loadShellDll(const char* dllpath);	//处理外壳, return dll size
	void initShellIndex(DWORD shellEndRva); // 初始化全局变量
	DWORD adjustShellReloc(DWORD shellBaseRva);// 设置dll重定位信息，返回个数
	DWORD adjustShellIat(DWORD shellBaseRva);// 设置由偏移造成的dll iat错误
	DWORD makeAppendBuf(DWORD shellStartRva, DWORD shellEndRva,  DWORD shellBaseRva); // 准备附加shellcode的buf
	void adjustPackpeHeaders(DWORD offset); // 调整加上shellcode后的pe头信息

 public:
	CSimpleDpack()
	{
		iniValue();
	}
	CSimpleDpack::CSimpleDpack(char* path);
	virtual ~CSimpleDpack()
	{
		release();
	}
	void iniValue();
	virtual	void release();
		
	DWORD loadPeFile(const char *path); //加载pe文件，返回isPE()值
	DWORD packPe(const char *dllpath, int type=DPACK_SECTION_DLZMA); // 加壳，失败返回0，成功返回pack数据大小
	DWORD unpackPe(int type=0); // 脱壳，其他同上（暂时不实现）
	DWORD savePe(const char *path); // 失败返回0，成功返回文件大小
	const char *getFilePath() const;
	CPEinfo* getExepe();
};
#endif