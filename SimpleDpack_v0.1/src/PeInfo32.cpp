#include "PeInfo32.hpp"
#include <fstream>
using namespace std;
/*Static*/
DWORD CPEinfo32::getPeMemSize(char *path)
{
	char buf[PE32HBUF_SIZE];
	readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	return getPeMemSize((LPBYTE)buf);
}
DWORD CPEinfo32::getPeMemSize(LPBYTE pFileBuf)
{
	if(pFileBuf==NULL) return 0;
	int res=CPEinfo::isPe((LPBYTE)pFileBuf);
	if(res <=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	return pNtHeader->OptionalHeader.SizeOfImage;
}
DWORD CPEinfo32::getOverlaySize(char *path)
{
	char buf[PE32HBUF_SIZE];
	int res;
	DWORD filesize;
	DWORD olaysize=0;

	filesize=getFileSize(path);
	if(filesize==0) return 0;
	readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	res=CPEinfo::isPe((LPBYTE)buf);
	if(res>0)
	{
		WORD sec_num;
		PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)buf;
		PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(buf+pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针

		sec_num=pNtHeader->FileHeader.NumberOfSections;
		olaysize=filesize-(pSecHeader[sec_num-1].PointerToRawData+pSecHeader[sec_num-1].SizeOfRawData);
	}
	return olaysize;
}
DWORD CPEinfo32::readOverlay(char *path,LPBYTE pOverlayBuf)
{
	if(pOverlayBuf==NULL) return 0;
	DWORD filesize;
	DWORD olaysize=0;
	LPBYTE pFileBuf;

	filesize=getFileSize(path);
	if(filesize==0) return 0;
	pFileBuf=new BYTE[filesize];
	readFile(path,pFileBuf,filesize);
	int res=CPEinfo::isPe(pFileBuf);
	if(res>0)
	{
		WORD sec_num=0;
		PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
		PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针

		sec_num=pNtHeader->FileHeader.NumberOfSections;
		olaysize=filesize-(pSecHeader[sec_num-1].PointerToRawData+pSecHeader[sec_num-1].SizeOfRawData);
		if(olaysize>0)
			memcpy(pOverlayBuf,pFileBuf+filesize-olaysize,olaysize);
	}
	delete[] pFileBuf;
	return olaysize;
}
DWORD CPEinfo32::addOverlay(char *path,LPBYTE pOverlay,DWORD size)//附加数据，此处不再对齐了
{
	if(pOverlay==NULL) return 0;
	ofstream fout(path,ios::binary | ios::app);
	if(fout.fail()) return 0;
	fout.seekp(0,ios::end);
	fout.write((const char *)pOverlay,size);
	fout.close();
	return size;
}

DWORD CPEinfo32::loadPeFile(char *path,
					LPBYTE pFileBuf,DWORD *FileBufSize,
					bool isMemAlign,
					LPBYTE pOverlayBuf,DWORD *OverlayBufSize)//失败返回0，成功返回读取总字节数,FileBufSize=0自动确认
{
	if(pFileBuf==NULL) return 0;
	DWORD loadsize=0;
	DWORD filesize;
	DWORD memsize;
	LPBYTE ptFileBuf;
	int res;

	filesize=getFileSize(path);
	ptFileBuf=new BYTE[filesize];
	res=readFile(path,(LPBYTE)pFileBuf,0);
	if(res<=0) return 0;
	res=CPEinfo::isPe((LPBYTE)pFileBuf);
	if(res>0)
	{
		WORD sec_num=0;
		int i;
		DWORD last_faddr;
		PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)ptFileBuf;
		PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(ptFileBuf+pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针
		memsize=pNtHeader->OptionalHeader.SizeOfImage;

		sec_num=pNtHeader->FileHeader.NumberOfSections;
		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		last_faddr=pSecHeader[sec_num-1].PointerToRawData+pSecHeader[sec_num-1].SizeOfRawData;
		
		if(isMemAlign==false)
		{
			memcpy(pFileBuf,ptFileBuf,filesize);
			if(FileBufSize!=NULL) *FileBufSize=filesize;
			if(last_faddr<filesize)
			{
				memcpy(pOverlayBuf,ptFileBuf+last_faddr,filesize-last_faddr);
				if(OverlayBufSize!=NULL) *OverlayBufSize=filesize-last_faddr;
			}
			loadsize=filesize;
		}
		else
		{
			memset(pFileBuf,0,memsize);
			loadsize=memsize;
			memcpy(pFileBuf,ptFileBuf,pNtHeader->OptionalHeader.SizeOfHeaders);//PE区段
			for(i=0;i<sec_num;i++)//赋值
			{
				memcpy(pFileBuf+pSecHeader[i].VirtualAddress,
					ptFileBuf+pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);
			}
			if(last_faddr<filesize)//附加数据
			{
				memcpy(pOverlayBuf,ptFileBuf+last_faddr,filesize-last_faddr);
				if(OverlayBufSize!=NULL) *OverlayBufSize=filesize-last_faddr;
				loadsize+=filesize-last_faddr;
			}
		}
		delete[] pFileBuf;
	}
	return loadsize;
}
DWORD CPEinfo32::savePeFile(char *path,
					LPBYTE pFileBuf,DWORD FileBufSize,
					bool isMemAlign,
					LPBYTE pOverlayBuf,DWORD OverlayBufSize)//失败返回0，成功返回写入总字节数
{
	if(pFileBuf==NULL) return 0;
	fstream fout;
	DWORD writesize;
	fout.open(path,ios::in);//判断文件是否存在
	if(!fout.fail())
		return 0;
	fout.close();
	fout.open(path,ios::out | ios::binary);
	writesize=CPEinfo::isPe((LPBYTE)pFileBuf);
	if(writesize<=0) return 0;
	if(isMemAlign==false)
	{
		fout.write((const char *)pFileBuf,FileBufSize);
		writesize=FileBufSize;
	}
	else
	{
		WORD sec_num=0;
		int i,j;
		DWORD last_peaddr;
		DWORD faddr;
		DWORD sectrva;
		DWORD sectsize;
		
		writesize=0;
		PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
		PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针	
		
		sec_num=pNtHeader->FileHeader.NumberOfSections;
		last_peaddr=pSecHeader[sec_num-1].PointerToRawData+pSecHeader[sec_num-1].SizeOfRawData;
		fout.write((const char *)pFileBuf,pNtHeader->OptionalHeader.SizeOfHeaders);//保存pe区
		writesize+=pNtHeader->OptionalHeader.SizeOfHeaders;
		for(i=0;i<sec_num;i++)
		{
			sectrva=pSecHeader[i].VirtualAddress;
			sectsize=toAlignment(pSecHeader[i].SizeOfRawData,pNtHeader->OptionalHeader.FileAlignment);
			faddr=fout.tellp();//防止地址不对
			if(faddr > pSecHeader[1].PointerToRawData)
				fout.seekp(pSecHeader[i].PointerToRawData);//防止重叠
			else if(faddr < pSecHeader[i].PointerToRawData)//防止区段少
				for(j=faddr;j<pSecHeader[i].PointerToRawData;j++)
					fout.put(0);
			fout.write((const char *)(pFileBuf+sectrva),sectsize);
			writesize+=sectsize;
		}
	}
	if(pOverlayBuf!=NULL && OverlayBufSize!=0)
	{
		fout.write((const char *)pOverlayBuf,OverlayBufSize);
		writesize+=OverlayBufSize;
	}
	fout.close();
	return writesize;
}
int CPEinfo32::getPeIndex(LPBYTE pFileBuf,PINDEX_PE32 peindex,bool isMemAlign)//返回isPe的值
{
	if(pFileBuf==NULL) return 0;
	
	int res;
	DWORD rva;
	DWORD offset;
	res=CPEinfo::isPe((LPBYTE)pFileBuf);
	if(res<=0) return res;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针

		peindex->pNtHeader=pNtHeader;
	peindex->pDataDir=pNtHeader->OptionalHeader.DataDirectory;
	peindex->pSectionHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));

	peindex->pwSectionNum=&pNtHeader->FileHeader.NumberOfSections;
	peindex->pdwImageSize=&pNtHeader->OptionalHeader.SizeOfImage;
	peindex->pdwHeaderSize=&pNtHeader->OptionalHeader.SizeOfHeaders;
	peindex->pdwFileAlign=&pNtHeader->OptionalHeader.FileAlignment;
	peindex->pdwMemAlign=&pNtHeader->OptionalHeader.SectionAlignment;
	peindex->pdwImageBase=&pNtHeader->OptionalHeader.ImageBase;
	peindex->pdwCodeBaseRva=&pNtHeader->OptionalHeader.BaseOfCode;
	peindex->pdwCodeSize=&pNtHeader->OptionalHeader.SizeOfCode;
	peindex->pdwOepRva=&pNtHeader->OptionalHeader.AddressOfEntryPoint;
	peindex->pdwIatBaseRva=&(peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	peindex->pdwIatSize=&(peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size);

	rva=peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	offset= isMemAlign==true ? rva:rva2faddr((LPBYTE)pFileBuf,rva);
	peindex->pExportDir= rva==0 ? 0 :(PIMAGE_EXPORT_DIRECTORY)(pFileBuf+offset);
	rva=peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	offset= isMemAlign==true ? rva:rva2faddr((LPBYTE)pFileBuf,rva);
	peindex->pImportDir= rva==0 ? 0 : (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuf+offset);
	rva=peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	offset= isMemAlign==true ? rva:rva2faddr((LPBYTE)pFileBuf,rva);
	peindex->pResourceDir= rva==0 ? 0 : (PIMAGE_RESOURCE_DIRECTORY)(pFileBuf+offset);
	rva=peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	offset= isMemAlign==true ? rva:rva2faddr((LPBYTE)pFileBuf,rva);
	peindex->pRelocDir= rva==0 ? 0 : (PIMAGE_BASE_RELOCATION)(pFileBuf+offset);
	rva=peindex->pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	offset= isMemAlign==true ? rva:rva2faddr((LPBYTE)pFileBuf,rva);
	peindex->pTlsDir= rva==0 ? 0 : (PIMAGE_TLS_DIRECTORY32)(pFileBuf+offset);
	return res;
}
int CPEinfo32::getPeIndex(char *path,PINDEX_PE32 peindex,bool isMemAlign)
{
	LPBYTE pFileBuf;
	DWORD size;
	int res;
	if(isMemAlign==true)
		size=getPeMemSize(path);
	else
		size=getFileSize(path);
	if(size==0) return 0;
	pFileBuf=new BYTE[size];
	size=loadPeFile(path,pFileBuf,NULL,isMemAlign);
	res=getPeIndex((LPBYTE)pFileBuf,peindex,isMemAlign);
	delete[] pFileBuf;
	return res;
}

DWORD CPEinfo32::getOepRva(LPBYTE pFileBuf)
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	return pNtHeader->OptionalHeader.AddressOfEntryPoint;
}
DWORD CPEinfo32::setOepRva(LPBYTE pFileBuf,DWORD rva)//返回原来的rva
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	DWORD oldrva= pNtHeader->OptionalHeader.AddressOfEntryPoint;
	pNtHeader->OptionalHeader.AddressOfEntryPoint=rva;
	return oldrva;
}
DWORD CPEinfo32::rva2faddr(LPBYTE pFileBuf,DWORD rva)
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	if(rva<=pNtHeader->OptionalHeader.SectionAlignment) return rva;//pe头部分
	int i=0;
	DWORD rvaoff;//rva相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针
	
	WORD sec_num=pNtHeader->FileHeader.NumberOfSections;
	for(i=0;i<sec_num;i++)
	{
		rvaoff=rva-pSecHeader[i].VirtualAddress;
		if(rvaoff>=0 && rvaoff<=pSecHeader[i].Misc.VirtualSize)
		{
			return rvaoff+pSecHeader[i].PointerToRawData;
		}
	}
	return 0;
}
DWORD CPEinfo32::faddr2rva(LPBYTE pFileBuf,DWORD faddr)
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	if(faddr<=pNtHeader->OptionalHeader.FileAlignment) return faddr;
	int i=0;
	DWORD faddroff;//faddr相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针
	
	WORD sec_num=pNtHeader->FileHeader.NumberOfSections;
	for(i=0;i<sec_num;i++)
	{
		faddroff=faddr-pSecHeader[i].PointerToRawData;
		if(faddroff>=0 && faddroff<=pSecHeader[i].SizeOfRawData)
		{
			return faddroff+pSecHeader[i].VirtualAddress;
		}
		i++;
	}
	return 0;
}
DWORD CPEinfo32::va2rva(LPBYTE pFileBuf,DWORD va)
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	res=va-pNtHeader->OptionalHeader.ImageBase;
	return res>0 ? res:0;
}
DWORD CPEinfo32::rva2va(LPBYTE pFileBuf,DWORD rva)
{
	if(pFileBuf==NULL) return 0;
	int res;
	res=CPEinfo::isPe(pFileBuf);
	if(res<=0) return 0;
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
	return rva+pNtHeader->OptionalHeader.ImageBase;
}
DWORD CPEinfo32::faddr2va(LPBYTE pFileBuf,DWORD faddr)
{
	if(pFileBuf==NULL) return 0;
	int rva=faddr2rva(pFileBuf,faddr);
	return rva2va(pFileBuf,rva);
}
DWORD CPEinfo32::va2faddr(LPBYTE pFileBuf,DWORD va)
{
	if(pFileBuf==NULL) return 0;
	int rva=va2rva(pFileBuf,va);
	return rva2faddr(pFileBuf,rva);
}

DWORD CPEinfo32::getOepRva(char *path)
{
	BYTE buf[PE32HBUF_SIZE];//判断pe只读取前0x100字节就行
	readFile(path,buf,PE32HBUF_SIZE);
	return getOepRva((LPBYTE)buf);
}
DWORD CPEinfo32::setOepRva(char *path,DWORD rva)
{
	DWORD oldrva;
	BYTE buf[PE32HBUF_SIZE];
	int readsize;
	readsize=readFile(path,buf,PE32HBUF_SIZE);
	if(readsize==0) return 0;
	oldrva=setOepRva((LPBYTE)buf,rva);
	if(oldrva==0) return 0;
	ofstream fout(path,ios::binary |ios::ate |ios::in);//ios::out则清空文件，ios::app每次写都是在最后，ios::ate可以用seekp
	fout.seekp(0,ios::beg);
	fout.write((const char *)buf,readsize);
	fout.close();
	return oldrva;
}
DWORD CPEinfo32::rva2faddr(char *path,DWORD rva)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return rva2faddr((LPBYTE)buf,rva);
}
DWORD CPEinfo32::faddr2rva(char *path,DWORD faddr)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return faddr2rva((LPBYTE)buf,faddr);
}
DWORD CPEinfo32::va2rva(char *path,DWORD va)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return va2rva((LPBYTE)buf,va);
}
DWORD CPEinfo32::rva2va(char *path,DWORD rva)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return rva2va((LPBYTE)buf,rva);
}
DWORD CPEinfo32::faddr2va(char *path,DWORD faddr)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return faddr2va((LPBYTE)buf,faddr);
}
DWORD CPEinfo32::va2faddr(char *path,DWORD va)
{
	char buf[PE32HBUF_SIZE];
	int size=readFile(path,(LPBYTE)buf,PE32HBUF_SIZE);
	if(size==0) return 0;
	return va2faddr((LPBYTE)buf,va);
}
/*Static end*/

/*constractor*/
CPEinfo32::CPEinfo32()
{
	iniValue();
}
CPEinfo32::CPEinfo32(char *path,bool isMemAlign)
{
	CPEinfo32();
	openPeFile(path,isMemAlign);
	getPeIndex();
}
CPEinfo32::CPEinfo32(LPBYTE pFileBuf,DWORD filesize,bool isCopyMem,bool isMemAlign)
{
	CPEinfo32();
	attachPeBuf(pFileBuf,filesize,isCopyMem,isMemAlign);
	getPeIndex();
}
void CPEinfo32::copy(const CPEinfo32 &pe32,bool isCopyMem)//默认拷贝函数
{
	attachPeBuf(pe32.getFileBuf(),pe32.getFileBufSize(),
						isCopyMem,pe32.isMemAlign(),
						pe32.getOverlayBuf(),pe32.getOverlayBufSize());
	strcpy(this->m_strFilePath,pe32.m_strFilePath);
	getPeIndex();
}
CPEinfo32::CPEinfo32(const CPEinfo32 &pe32)
{
	copy(pe32,true);
}
/*constractor end*/

int CPEinfo32::attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
						bool isCopyMem,bool isMemAlign,
						LPBYTE pOverlayBuf,DWORD dwOverLayBufSize)
{
	return CPEinfo::attachPeBuf(pFileBuf,dwFileBufSize,isCopyMem,isMemAlign,pOverlayBuf,dwOverLayBufSize);
}
DWORD CPEinfo32::openPeFile(char *path,bool isMemAlign)//暂时不用内存映射，不用loadPeFile函数，若是filealign节省一次内存载入	
{
	LPBYTE pFileBuf=NULL;
	DWORD filesize;
	DWORD memsize;
	DWORD loadsize=0;
	int res;
	
	//释放之前资源
	releaseAllBuf();
	closePeFile();
	m_isMemAlign=isMemAlign;

	filesize=getFileSize(path);
	pFileBuf=new BYTE[filesize];
	res=readFile(path,(LPBYTE)pFileBuf,0);
	if(res<=0) 
		return -3;
	res=CPEinfo::isPe((LPBYTE)pFileBuf);
	if(res>0)
	{
		WORD sec_num=0;
		int i;
		DWORD last_faddr;
		PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)pFileBuf;
		PIMAGE_NT_HEADERS32 pNtHeader=(PIMAGE_NT_HEADERS32)(pFileBuf+pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader+sizeof(IMAGE_NT_HEADERS32));//注意byte型指针
		memsize=pNtHeader->OptionalHeader.SizeOfImage;

		sec_num=pNtHeader->FileHeader.NumberOfSections;
		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		last_faddr=pSecHeader[sec_num-1].PointerToRawData+pSecHeader[sec_num-1].SizeOfRawData;
		
		if(isMemAlign==false)
		{
			m_pFileBuf=pFileBuf;
			m_dwFileBufSize=last_faddr;
			m_dwOverlayBufSize=filesize-last_faddr;
			if(last_faddr<filesize)
			{
				m_pOverlayBuf=pFileBuf+last_faddr;
				m_dwOverlayBufSize=filesize-last_faddr;
			}
			loadsize=filesize;
		}
		else
		{
			loadsize=memsize;
			m_dwFileBufSize=memsize;
			m_pFileBuf=new BYTE[memsize];
			memset(m_pFileBuf,0,memsize);
			memcpy(m_pFileBuf,pFileBuf,pNtHeader->OptionalHeader.SizeOfHeaders);
			for(i=0;i<sec_num;i++)//赋值
			{
				memcpy(m_pFileBuf+pSecHeader[i].VirtualAddress,
					pFileBuf+pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);

			}
			if(last_faddr<filesize)
			{
				m_dwOverlayBufSize=filesize-last_faddr;
				m_pOverlayBuf=new BYTE[m_dwOverlayBufSize];
				memcpy(m_pOverlayBuf,pFileBuf+last_faddr,m_dwOverlayBufSize);
				loadsize+=m_dwOverlayBufSize;
			}
			delete[] pFileBuf;
		}
	}
	return loadsize;
}
DWORD CPEinfo32::savePeFile(char *path)
{
	return savePeFile(path,m_pFileBuf,m_dwFileBufSize,
					  m_isMemAlign,
					  m_pOverlayBuf,m_dwOverlayBufSize);
}
void CPEinfo32::iniValue()								
{
	CPEinfo::iniValue();
	memset(&m_pe32Index,0,sizeof(m_pe32Index));	
}
int CPEinfo32::isPe()										
{	
	int res=CPEinfo::isPe((char *)m_pFileBuf);
	if(res<=0)
		releaseFileBuf();
	return res;
}
int CPEinfo32::getPeIndex() 
{
	return getPeIndex(m_pFileBuf,&m_pe32Index,m_isMemAlign);
}
DWORD CPEinfo32::getOepRva()
{
	return getOepRva((LPBYTE)m_pFileBuf);
}
DWORD CPEinfo32::setOepRva(DWORD rva)
{
	return setOepRva((LPBYTE)m_pFileBuf,rva);
}
CPEinfo32& CPEinfo32::operator=(CPEinfo32 &pe32)
{
	copy(pe32,true);
	return *this;
}
DWORD CPEinfo32::rva2faddr(DWORD rva) const
{
	return rva2faddr(m_pFileBuf,rva);
}
DWORD CPEinfo32::faddr2rva(DWORD faddr) const
{
	return faddr2rva(m_pFileBuf,faddr);
}
DWORD CPEinfo32::va2rva(DWORD va) const
{
	return va2rva(m_pFileBuf,va);
}
DWORD CPEinfo32::rva2va(DWORD rva) const
{
	return rva2va(m_pFileBuf,rva);
}
DWORD CPEinfo32::faddr2va(DWORD faddr) const
{
	return faddr2va(m_pFileBuf,faddr);
}
DWORD CPEinfo32::va2faddr(DWORD va) const
{
	return va2faddr(m_pFileBuf,va);
}