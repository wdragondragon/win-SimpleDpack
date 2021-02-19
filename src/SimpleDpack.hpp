#include <Windows.h>
#include "PeInfo.hpp"
extern "C" // c++中引用c必须要这样
{
    #include <Psapi.h>	
    #include "dpackType.h"
	#include "dpackCode.h"
	#include "dunpackCode.h"
}
#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H
/*
	pack the pe file class
*/

typedef struct _DPACKSECT_INDEX32
{
	LPBYTE packBuf;
	DWORD  packBufSize;
	DWORD  srcRva;//若此项为0，则添加到最后一个区段
	DWORD  srcMemSize;
}DPACKSECT_INDEX, * PDPACKSECT_INDEX;

class CSimpleDpack
{
public:
	static DWORD dlzmaPack(LPBYTE* dst, LPBYTE src, DWORD lzmasize, double maxmul = 2.0);

private:
	char m_strFilePath[MAX_PATH];

protected:
	CPEinfo m_exepe;
	CPEinfo m_shellpe;
	PDPACK_HDADER m_gShellHeader;
	HMODULE m_hShell;

	WORD m_dpackSectNum;
	DPACKSECT_INDEX m_dpackIndex[MAX_DPACKSECTNUM];

	WORD iniDpackIndex();//返回原来dpackIndex数量
	WORD addDpackIndex(LPBYTE packBuf, DWORD packBufSize, DWORD srcRva = 0, DWORD srcMemSize = 0);//增加dpack索引
	DWORD packSection(int type=1);	//pack各区段
	DWORD adjustShellReloc(LPBYTE pShellBuf, HMODULE hShell, DWORD shellBaseRva);//设置dll重定位信息，返回个数
	DWORD adjustShellIat(LPBYTE pShellBuf, HMODULE hShell, DWORD shellBaseRva);//设置由偏移造成的dll iat错误
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
	DWORD packPe(const char *dllpath, int type=0); //加壳，失败返回0，成功返回pack数据大小
	DWORD unpackPe(int type=0); // 脱壳，其他同上（暂时不实现）
	DWORD savePe(const char *path); // 失败返回0，成功返回文件大小
	const char *getFilePath() const;
	CPEinfo* getExepe();
};
#endif