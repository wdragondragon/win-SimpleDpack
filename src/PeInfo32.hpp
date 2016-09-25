#include "PeInfo.hpp"
#ifndef _PEINFO32_H
#define _PEINFO32_H
/*
	peinfo32 v0.1
	coded by devseed
*/
#define PE32HBUF_SIZE 0X500 //PE32头最大长度
typedef struct _INDEX_PE32	//PE信息索引表
{
	PDWORD					pdwImageSize;		//镜像大小
	PWORD					pwSectionNum;		//区块数量
	PDWORD					pdwHeaderSize;	//文件头大小
	PDWORD					pdwFileAlign;		//文件对齐
	PDWORD					pdwMemAlign;		//内存对齐
	PDWORD					pdwImageBase;		//镜像基址
		
	PDWORD					pdwCodeBaseRva;	//代码基址
	PDWORD					pdwCodeSize;		//代码大小
	PDWORD					pdwOepRva;			//OEP地址(rva)
	PDWORD					pdwIatBaseRva;		//IAT所在段基址
	PDWORD					pdwIatSize;		//IAT所在段大小
		
	PIMAGE_NT_HEADERS			pNtHeader;			//NT头
	PIMAGE_DATA_DIRECTORY		pDataDir;		        //数据目录
	PIMAGE_SECTION_HEADER		pSectionHeader;		//第一个SECTION结构体指针
	PIMAGE_EXPORT_DIRECTORY		pExportDir;		    //导出表表信息
	PIMAGE_IMPORT_DESCRIPTOR	pImportDir;			//导入表信息
	PIMAGE_RESOURCE_DIRECTORY   pResourceDir;		    //资源目录
	PIMAGE_BASE_RELOCATION		pRelocDir;			//重定位表信息
	PIMAGE_TLS_DIRECTORY32      pTlsDir;				//tls信息
	//延时导入，.net什么的暂时不考虑
}INDEX_PE32,*PINDEX_PE32;

class CPEinfo32:public CPEinfo//记录pe信息的类
{

	public:	
		//静态函数不能有虚函数，所以这里不再在基类中用
		static DWORD getPeMemSize(char *path);
		static DWORD getPeMemSize(LPBYTE pFileBuf);
		static DWORD getOverlaySize(char *path);
		static DWORD readOverlay(char *path,LPBYTE pOverlay);
		static DWORD addOverlay(char *path,LPBYTE pOverlay,DWORD size);
		static DWORD loadPeFile(char *path,
							LPBYTE pFileBuf,DWORD *FileBufSize,
							bool isMemAlign=false,
							LPBYTE pOverlayBuf=NULL,DWORD *OverlayBufSize=0);//失败返回0，成功返回读取总字节数
		static DWORD savePeFile(char *path,
							LPBYTE pFileBuf,DWORD FileBufSize,
							 bool isMemAlign=false,
							LPBYTE pOverlayBuf=NULL,DWORD OverlayBufSize=0);//失败返回0，成功返回写入总字节数
		static int getPeIndex(LPBYTE pFileBuf,PINDEX_PE32 peindex,bool isMemAlign=false);//返回isPe的值
		static int getPeIndex(char *path,PINDEX_PE32 peindex,bool isMemAlign=false);
		
		//缓存区PE信息的处理
		static DWORD getOepRva(LPBYTE pFileBuf);//返回Rva
		static DWORD setOepRva(LPBYTE pFileBuf,DWORD rva);//返回原来的rva
		static DWORD rva2faddr(LPBYTE pFileBuf,DWORD rva);
		static DWORD faddr2rva(LPBYTE pFileBuf,DWORD faddr);
		static DWORD va2rva(LPBYTE pFileBuf,DWORD va);
		static DWORD rva2va(LPBYTE pFileBuf,DWORD rva);
		static DWORD faddr2va(LPBYTE pFileBuf,DWORD faddr);
		static DWORD va2faddr(LPBYTE pFileBuf,DWORD va);
		
		//文件中PE信息处理	
		static DWORD getOepRva(char *path);
		static DWORD setOepRva(char *path,DWORD rva);
		static DWORD rva2faddr(char *path,DWORD rva);//rva和file offset转换，无效返回0
		static DWORD faddr2rva(char *path,DWORD faddr);
		static DWORD va2rva(char *path,DWORD va);
		static DWORD rva2va(char *path,DWORD rva);
		static DWORD faddr2va(char *path,DWORD faddr);
		static DWORD va2faddr(char *path,DWORD va);

	public:
		INDEX_PE32 m_pe32Index;

	public:
		//构造函数与运算符重载
		CPEinfo32();
		CPEinfo32(char *path,bool isMemAlign=true);
		CPEinfo32(LPBYTE pFileBuf,DWORD filesize,bool isCopyMem=false,bool isMemAlign=true);
		void copy(const CPEinfo32 &pe32,bool isCopyMem=true);//默认拷贝函数
		CPEinfo32(const CPEinfo32 &pe32);
		CPEinfo32 &operator=(CPEinfo32 &pe32);
		
		//PE文件基本操作（新增，其他的调用基类的）
		DWORD openPeFile(char *path,bool isMemAlign=true);		//打开pe文件，isMemAlign=1以内存方式对齐
		int attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
						bool isCopyMem=true,bool isMemAlign=true,
						LPBYTE pOverlayBuf=NULL,DWORD dwOverLayBufSize=0);//附加外部的pe数据
		DWORD savePeFile(char *path);								//保存缓冲区pe文件
		void iniValue();								//各个变量赋初值
		int isPe() ;										//判断文件是否为有效pe文件(-1非dos,-2非pe,010b:32exe,020b:64exe)
		int getPeIndex() ;								//获得pe文件信息索引
		DWORD getOepRva();
		DWORD setOepRva(DWORD rva);
		

		//地址转换
		DWORD rva2faddr(DWORD rva) const;
		DWORD faddr2rva(DWORD faddr) const;
		DWORD va2rva(DWORD va) const;
		DWORD rva2va(DWORD rva) const;
		DWORD faddr2va(DWORD faddr) const;
		DWORD va2faddr(DWORD va) const;
};
#endif