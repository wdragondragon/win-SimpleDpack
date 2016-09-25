#include <Windows.h>
#include "PeInfo.hpp"
extern "C" // c++中引用c必须要这样
{
#include "dpackType.h"
#include "dpackCode.h"
#include "dunpackCode.h"
}
#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H
/*
	pack the pe file class
*/
class CSimpleDpack
{
	private:
		char m_strFilePath[MAX_PATH];
	protected:
		DWORD dlzmaPack(LPBYTE *dst,LPBYTE src,DWORD lzmasize,double maxmul=2.0);
	public:
		CSimpleDpack()
		{
			iniValue();
		}
		virtual ~CSimpleDpack(){}
		void iniValue();
		virtual	void release()=0;
		virtual DWORD loadPeFile(char *path)=0;//加载pe文件，返回isPE()值
		virtual DWORD packPe(int type,char *dllpath)=0;//加壳，失败返回0，成功返回pack数据大小
		virtual DWORD unpackPe(int type=0)=0;//脱壳，其他同上（暂时不实现）
		virtual DWORD savePe(char *path)=0;//失败返回0，成功返回文件大小
		const char *getFilePath() const;
};
#endif