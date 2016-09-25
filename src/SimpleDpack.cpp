#include "SimpleDpack.hpp"
#include "lzma\lzmalib.h"
void CSimpleDpack::iniValue()
{
	memset(m_strFilePath,0,MAX_PATH);
}
DWORD CSimpleDpack::dlzmaPack(LPBYTE *dst,LPBYTE src,DWORD lzmasize,double maxmul)
{
	if(src==NULL) return 0;
	for(double m=1;m<=maxmul;m+=0.1)
	{
		if(*dst!=NULL) 
		{
			delete[] dst;
			lzmasize=(DWORD)(m*(double)lzmasize);//防止分配缓存区空间过小
		}
		*dst=new BYTE[lzmasize];
		DWORD res=::dlzmaPack(*dst,src,lzmasize);
		if(res > 0 ) return res;
	}
	return 0;
}
 const char* CSimpleDpack::getFilePath() const
 {
	 return m_strFilePath;
 }