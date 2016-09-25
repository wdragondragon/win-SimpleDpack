#include "PeInfo.hpp"
#include <fstream>
using namespace std;
/*Static*/
DWORD CPEinfo::getFileSize(char *path)
{
	ifstream fin(path,ios::binary);
	if(fin.fail()) 
		return 0;
	fin.seekg(0,ios::end);
	DWORD fsize=fin.tellg();
	fin.close();
	return fsize;
}
DWORD CPEinfo::readFile(char *path,LPBYTE pFileBuf,DWORD size)//读文件，size为要读的数(0读取全部)，返回读取字节数，放到pFileBuf中
{
	if(pFileBuf==NULL) return 0;
	int fsize;
	ifstream fin(path,ios::binary);
	if(fin.fail()) 
		return 0;
	fin.seekg(0,ios::end);
	fsize=fin.tellg();
	fin.seekg(0,ios::beg);
	if(size==0 || fsize<size) 
		size=fsize;
	fin.read((char *)pFileBuf,size);
	fin.close();
	return size;
}
int CPEinfo::isPe(LPBYTE pFileBuf)
{
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE) //"MZ"
		return -1;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	if(pNtHeader->Signature!=IMAGE_NT_SIGNATURE) //"PE\0\0"
		return -2;
	return pNtHeader->OptionalHeader.Magic;
}
int CPEinfo::isPe(char *path)
{
	const int BUFSIZE=0x300;
	char buf[BUFSIZE];//判断pe只读取前0x100字节就行
	if(readFile(path,(LPBYTE)buf,BUFSIZE)==0)
		return -3;
	return isPe((LPBYTE)buf);
}
DWORD CPEinfo::toAlignment(DWORD num,DWORD align)
{
	DWORD r;
	r=num%align;
	num-=r;
	if(r!=0) num+=align;
	return num;
}
/*Static end*/


/*Virtual functions*/
void CPEinfo::iniValue()
{
	m_isMemAlign=true;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
	m_isMemAlloc=true;//是否内存为此处分配的
		
	memset(m_strFilePath,0,MAX_PATH);
	m_pFileBuf=0;		//PE文件缓冲区
	m_dwFileBufSize=0;	//PE文件缓存区大小
	m_pOverlayBuf=NULL;	//PE附加数据
	m_dwOverlayBufSize=0;//PE附加数据大小
}
int CPEinfo::attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
						bool isCopyMem,bool isMemAlign,
						LPBYTE pOverlayBuf,DWORD dwOverLayBufSize)
{
	if(pFileBuf==NULL) return 0;
	m_isMemAlloc=isCopyMem;
	m_isMemAlign=isMemAlign;
	releaseAllBuf();
	closePeFile();
	int res=isPe((LPBYTE)pFileBuf);
	if(res>0)
	{
		if(isCopyMem)
		{
			m_pFileBuf=new BYTE[dwFileBufSize];
			m_pOverlayBuf=new BYTE[dwOverLayBufSize];
			memcpy(m_pFileBuf,pFileBuf,dwFileBufSize);
			if(pOverlayBuf!=NULL)
				memcpy(m_pOverlayBuf,pOverlayBuf,dwOverLayBufSize);
		}
		else
		{
			m_pFileBuf=pFileBuf;
			m_pOverlayBuf=pOverlayBuf;
		}
		m_dwFileBufSize=dwFileBufSize;
		m_dwOverlayBufSize=dwOverLayBufSize;
		getPeIndex();
	}
	return res;
}
int CPEinfo::closePeFile()								
{
	if(m_strFilePath[0]!=0)
		memset(m_strFilePath,0,MAX_PATH);
	return 0;
}
int CPEinfo::releaseFileBuf()							
{
	int res=0;
	if(m_isMemAlloc==true && m_pFileBuf!=NULL)
	{
		delete[] m_pFileBuf;
		res++;
	}
	if(m_isMemAlign==false)
		releaseOverlayBuf();
	m_pFileBuf=NULL;
	m_dwFileBufSize=0;
	return 0;
}
int CPEinfo::releaseOverlayBuf()
{
	int res=0;
	if(m_isMemAlloc==true &&m_isMemAlign==true && m_pOverlayBuf!=NULL )
	{
		delete[] m_pOverlayBuf;
		res++;
	}
	m_pOverlayBuf=NULL;
	m_dwOverlayBufSize=0;
	return 0;
}
int CPEinfo::releaseAllBuf()
{
	int res=0;
	res+=releaseFileBuf();
	res+=releaseOverlayBuf();
	return res;
}
/*Virtual functions end*/


/*Construators*/
/*Constructors end*/


bool CPEinfo::isMemAlign() const
{
	return m_isMemAlign;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
}
bool CPEinfo::isMemAlloc() const
{
	return m_isMemAlloc;//是否内存为此处分配的
}
const char* const CPEinfo::getFilePath() const
{
	return m_strFilePath;
}
LPBYTE CPEinfo::getFileBuf() const
{
	return m_pFileBuf;//PE文件缓冲区
}
DWORD CPEinfo::getFileBufSize() const
{
	return m_dwFileBufSize;//PE文件缓存区大小
}
LPBYTE CPEinfo::getOverlayBuf() const
{
	return m_pOverlayBuf;
}
DWORD CPEinfo::getOverlayBufSize() const
{
	return m_dwOverlayBufSize;
}