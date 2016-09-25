#include <Windows.h>
#ifndef _PEINFO_H
#define _PEINFO_H
/*
	peinfo v0.1
	coded by devseed
	the base class
	in order to adapter other os I won't us system api directly too much(excet loadlibrary)
*/
typedef struct _RELOCOFFSET
{
	WORD offset : 12;			//偏移值
	WORD type	: 4;			//重定位属性(方式)
}RELOCOFFSET,*PRELOCOFFSET;
class CPEinfo
{
	public:
		//文件处理
		static DWORD getFileSize(char *path);
		static DWORD readFile(char *path,LPBYTE pFileBuf,DWORD size=0);//从头读文件，size为要读的数(0读取全部)，返回读取字节数，放到pFileBuf中
		static int isPe(LPBYTE  pFileBuf);
		static int isPe(char *path);
		static DWORD toAlignment(DWORD num,DWORD align);

	protected:
		//假设exe文件不超过4g
		bool m_isMemAlign;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
		bool m_isMemAlloc;//是否内存为此处分配的
		char					m_strFilePath[MAX_PATH]; //PE文件路径
		LPBYTE					m_pFileBuf;			//PE文件缓冲区
		DWORD					m_dwFileBufSize;	//PE文件缓存区大小
		LPBYTE					m_pOverlayBuf;		//PE附加数据缓冲区，若memalign则重新分配，否则指向相应位置，没有为NULL
		DWORD					m_dwOverlayBufSize;	//PE附加数据大小
		
	public:
		CPEinfo()
		{
			iniValue();
		}
		virtual ~CPEinfo()
		{
			closePeFile();
			releaseFileBuf();
		}
		CPEinfo(const CPEinfo &pe32);
		//PE文件基本操作(虚函数)
		virtual DWORD openPeFile(char *path,bool isMemAlign=true)=0;		//打开pe文件，isMemAlign=1以内存方式对齐
		virtual DWORD savePeFile(char *path)=0;								//保存缓冲区pe文件
		virtual int isPe()=0;								//判断文件是否为有效pe文件(-1非dos,-2非pe,010b:32exe,020b:64exe)
		virtual int getPeIndex()=0;								//获得pe文件信息索引

		
		virtual void iniValue();						//各个变量赋初值
		virtual int attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
						bool isCopyMem=true,bool isMemAlign=true,
						LPBYTE pOverlayBuf=NULL,DWORD dwOverLayBufSize=0);//附加外部的pe数据
		virtual int closePeFile();								//关闭pe文件
		virtual int releaseFileBuf();							//释放文件的缓冲区
		virtual int releaseOverlayBuf();						//释放overlay部分缓冲区
		virtual int releaseAllBuf();							//释放全部缓冲区

		
		//获取各私有变量
		bool isMemAlign() const;								//true内存对齐，false文件对齐
		bool isMemAlloc() const;								//内存是否为new出来的
		const char* const getFilePath() const;
		LPBYTE getFileBuf() const;
		DWORD getFileBufSize() const;
		LPBYTE getOverlayBuf() const;
		DWORD getOverlayBufSize() const;
};
#endif