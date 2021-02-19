#include <Windows.h>
#ifndef _PEINFO_H
#define _PEINFO_H
/*
	peinfo v0.2
	designed by devseed
	the base class
	in order to adapter other os I won't us system api directly too much(excet loadlibrary)
*/
typedef struct _RELOCOFFSET
{
	WORD offset : 12;			//偏移值
	WORD type	: 4;			//重定位属性(方式)
}RELOCOFFSET,*PRELOCOFFSET;

#define PEHBUF_SIZE 0X500 //PE32头最大长度

class CPEinfo
{
public:
	//文件处理
	static DWORD getFileSize(const char *path);
	static DWORD readFile(const char *path, LPBYTE pFileBuf,DWORD size=0);//从头读文件，size为要读的数(0读取全部)，返回读取字节数，放到pFileBuf中
	static int isPe(LPBYTE  pFileBuf);
	static int isPe(const char *path);
	static DWORD toAlignment(DWORD num,DWORD align);

	// pe 参数
	static PIMAGE_NT_HEADERS getNtHeader(LPBYTE pFileBuf);
	static PIMAGE_FILE_HEADER getFileHeader(LPBYTE pFileBuf);
	static PIMAGE_OPTIONAL_HEADER getOptionalHeader(LPBYTE pFileBuf);
	static PIMAGE_DATA_DIRECTORY getImageDataDirectory(LPBYTE pFileBuf);
	static PIMAGE_SECTION_HEADER getSectionHeader(LPBYTE pFileBuf);
	static PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(LPBYTE pFileBuf, bool bFromFile);

	static DWORD getPeMemSize(const char* path);
	static DWORD getPeMemSize(LPBYTE pFileBuf);
	static DWORD getOverlaySize(const char* path); 
	static DWORD getOverlaySize(LPBYTE pFileBuf, DWORD filesize); // 即为pe后面附加的数据
	static DWORD readOverlay(const char* path, LPBYTE pOverlay);
	static DWORD readOverlay(LPBYTE pFileBuf, DWORD filesize, LPBYTE pOverlay);
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);

	// 地址转换
	static DWORD getOepRva(const char* path);
	static DWORD getOepRva(LPBYTE pFileBuf);//返回Rva
	static DWORD setOepRva(const char* path, DWORD rva);
	static DWORD setOepRva(LPBYTE pFileBuf, DWORD rva);//返回原来的rva
		
	static DWORD rva2faddr(const char* path, DWORD rva);//rva和file offset转换，无效返回0
	static DWORD rva2faddr(LPBYTE pFileBuf, DWORD rva);
	static DWORD faddr2rva(const char* path, DWORD faddr);
	static DWORD faddr2rva(LPBYTE pFileBuf, DWORD faddr);
#ifdef _WIN64
	static DWORD va2rva(const char* path, ULONGLONG va);
	static DWORD va2rva(LPBYTE pFileBuf, ULONGLONG va);
	static ULONGLONG rva2va(const char* path, DWORD rva);
	static ULONGLONG rva2va(LPBYTE pFileBuf, DWORD rva);
	static ULONGLONG faddr2va(const char* path, DWORD faddr);
	static ULONGLONG faddr2va(LPBYTE pFileBuf, DWORD faddr);
	static DWORD va2faddr(const char* path, ULONGLONG va);
	static DWORD va2faddr(LPBYTE pFileBuf, ULONGLONG va);
#else
	static DWORD va2rva(const char* path, DWORD va);
	static DWORD va2rva(LPBYTE pFileBuf, DWORD va);
	static DWORD rva2va(const char* path, DWORD rva);
	static DWORD rva2va(LPBYTE pFileBuf, DWORD rva);
	static DWORD faddr2va(const char* path, DWORD faddr);
	static DWORD faddr2va(LPBYTE pFileBuf, DWORD faddr);
	static DWORD va2faddr(const char* path, DWORD va);
	static DWORD va2faddr(LPBYTE pFileBuf, DWORD va);
#endif
	// pe 存取
	static DWORD loadPeFile(const char* path,
		LPBYTE pFileBuf, DWORD* FileBufSize,
		bool bMemAlign = false,
		LPBYTE pOverlayBuf = NULL, DWORD* OverlayBufSize = 0);//失败返回0，成功返回读取总字节数
	static DWORD savePeFile(const char* path,
		LPBYTE pFileBuf, DWORD FileBufSize,
		bool isMemAlign = false,
		LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);//失败返回0，成功返回写入总字节数

protected:
	//假设exe文件不超过4g
	bool m_bMemAlign;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
	bool m_bMemAlloc;//是否内存为此处分配的
	char m_szFilePath[MAX_PATH]; //PE文件路径
		
	LPBYTE	m_pFileBuf;			//PE文件缓冲区
	DWORD	m_dwFileBufSize;	//PE文件缓存区大小
	LPBYTE	m_pOverlayBuf;		//PE附加数据缓冲区，若memalign则重新分配，否则指向相应位置，没有为NULL
	DWORD	m_dwOverlayBufSize;	//PE附加数据大小

public:
	CPEinfo()
	{
		iniValue();
	}
	virtual ~CPEinfo()
	{
		closePeFile();
	}
	//构造函数与运算符重载
	CPEinfo(const char* path, bool isMemAlign = true);
	CPEinfo(LPBYTE pFileBuf, DWORD filesize, bool isCopyMem = false, bool isMemAlign = true);
	void copy(const CPEinfo& pe, bool isCopyMem = true);//默认拷贝函数
	CPEinfo(const CPEinfo& pe);
	CPEinfo& operator=(CPEinfo& pe);
		
	//PE文件基本操作
	DWORD openPeFile(const char *path,bool bMemAlign=true);//打开pe文件，isMemAlign=1以内存方式对齐
	DWORD savePeFile(const char *path); //保存缓冲区pe文件
	int isPe();	//判断文件是否为有效pe文件(-1非dos,-2非pe,010b:32exe,020b:64exe)
	void iniValue(); //各个变量赋初值
	int attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
					bool isCopyMem=true,bool isMemAlign=true,
					LPBYTE pOverlayBuf=NULL,DWORD dwOverLayBufSize=0);//附加外部的pe数据
	void closePeFile(); //关闭pe文件并释放空间
		
	// 地址转换
	DWORD getOepRva();
	DWORD setOepRva(DWORD rva);
	DWORD rva2faddr(DWORD rva) const;
	DWORD faddr2rva(DWORD faddr) const;
#ifdef _WIN64
	DWORD va2rva(ULONGLONG va) const;
	ULONGLONG rva2va(DWORD rva) const;
	ULONGLONG faddr2va(faddr) const;
	DWORD va2faddr(DWORD ULONGLONG) const;
#else
	DWORD va2rva(DWORD va) const;
	DWORD rva2va(DWORD rva) const;
	DWORD faddr2va(DWORD faddr) const;
	DWORD va2faddr(DWORD va) const;
#endif
	//获取各私有变量
	bool isMemAlign() const; //true内存对齐，false文件对齐
	bool isMemAlloc() const; //内存是否为new出来的
	const char* const getFilePath() const;
	LPBYTE getFileBuf() const;
	DWORD getFileBufSize() const;
	LPBYTE getOverlayBuf() const;
	DWORD getOverlayBufSize() const;
	PIMAGE_NT_HEADERS getNtHeader();
	PIMAGE_FILE_HEADER getFileHeader();
	PIMAGE_OPTIONAL_HEADER getOptionalHeader();
	PIMAGE_DATA_DIRECTORY getImageDataDirectory();
	PIMAGE_SECTION_HEADER getSectionHeader();
	PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor();
};
#endif