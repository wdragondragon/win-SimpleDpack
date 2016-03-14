#include <string.h>
#include "capstone-3.0.4-win32\capstone.h"
#include "lzma\lzmalib.h"
#include "PeInfo32.hpp"
#include "DpackType.h"
#include "SimpleDpack.hpp"
#ifndef _SIMPLEDPACK32_H
#define _SIMPLEDPACK32_H
/*
	simpledpack packer for win32 exe
	determine that the data on memery unchanged
*/
typedef struct _DPACKSECT_INDEX32
{
	LPBYTE packBuf;
	DWORD  packBufSize;
	DWORD  srcRva;//若此项为0，则添加到最后一个区段
	DWORD  srcMemSize;
}DPACKSECT_INDEX32,*PDPACKSECT_INDEX32;
class CSimpleDpack32 :public CSimpleDpack
{
	protected:
		CPEinfo32 m_pe32;
		CPEinfo32 m_shellpe32;
		PDPACK_HDADER32 m_gShellHeader32;
		DWORD m_hShell;
		
		WORD m_dpackSectNum;
		DPACKSECT_INDEX32 m_dpackIndex[MAX_DPACKSECTNUM];
		
		WORD iniDpackIndex();//返回原来dpackIndex数量
		WORD addDpackIndex(LPBYTE packBuf,DWORD packBufSize,DWORD srcRva=0,DWORD srcMemSize=0);//增加dpack索引
		DWORD sectProc(int type);	//处理各区段
		DWORD shelldllProc(int type,char *dllpath);	//处理外壳
		DWORD setShellReloc(LPBYTE pShellBuf, DWORD hShell,DWORD shellBaseRva);//设置dll重定位信息，返回个数
		DWORD setShellIat(LPBYTE pShellBuf, DWORD hShell,DWORD shellBaseRva);//设置由偏移造成的dll iat错误
	public:
		CSimpleDpack32()
		{
			iniValue();
		}
		CSimpleDpack32(char *path);
		~CSimpleDpack32()
		{
			release();
		}
		void iniValue();
		void release();
		
		DWORD loadPeFile(char *path);//加载pe文件，返回openPE()值
		DWORD packPe(int type=0,char *dllpath="simpledpackshell32.dll");//加壳，失败返回0，成功返回pack数据大小
		DWORD unpackPe(int type=0);//脱壳，其他同上（暂时不实现）
		DWORD savePe(char *path);//失败返回0，成功返回文件大小
		CPEinfo32* getPe();
};

#endif