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

typedef struct _DPACKSECT_INDEX
{
	LPBYTE PackedBuf;
	DWORD  PackedSize;
	DWORD  OrgRva;//若此项为0，则添加到最后一个区段
	DWORD  OrgMemSize;
}DPACKSECT_INDEX, * PDPACKSECT_INDEX;

class CSimpleDpack
{
public:
	static DWORD dlzmaPack(LPBYTE* dst, LPBYTE src, DWORD lzmasize, double maxmul = 2.0); // 加壳lzma压缩算法

private:
	char m_strFilePath[MAX_PATH];

protected:
	CPEedit m_exepe; // 需要加壳的exe pe结构
	CPEedit m_shellpe; // 壳的pe结构
	PDPACK_HDADER m_gShellHeader; // dll中的导出结构
	HMODULE m_hShell; // 壳dll的句柄

	WORD m_dpackSectNum; 
	DPACKSECT_INDEX m_dpackIndex[MAX_DPACKSECTNUM]; // 加壳区段索引

	WORD iniDpackIndex();//返回原来dpackIndex数量
	WORD addDpackIndex(LPBYTE packBuf, DWORD packBufSize, DWORD srcRva = 0, DWORD OrgMemSize = 0);//增加dpack索引
	DWORD packSection(int type=1);	//pack各区段
	DWORD adjustShellReloc(DWORD shellBaseRva);//设置dll重定位信息，返回个数
	DWORD adjustShellIat(DWORD shellBaseRva);//设置由偏移造成的dll iat错误
	DWORD loadShellDll(const char* dllpath, int type=1);	//处理外壳

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
	DWORD packPe(const char *dllpath, int type=0); // 加壳，失败返回0，成功返回pack数据大小
	DWORD unpackPe(int type=0); // 脱壳，其他同上（暂时不实现）
	DWORD savePe(const char *path); // 失败返回0，成功返回文件大小
	const char *getFilePath() const;
	CPEinfo* getExepe();
};
#endif