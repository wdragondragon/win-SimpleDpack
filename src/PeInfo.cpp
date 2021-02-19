#include "PeInfo.hpp"
#include <fstream>
using namespace std;
/*Static*/
DWORD CPEinfo::getFileSize(const char *path)
{
	ifstream fin(path,ios::binary);
	if(fin.fail()) return 0;
	fin.seekg(0,ios::end);
	DWORD fsize=fin.tellg();
	fin.close();
	return fsize;
}

DWORD CPEinfo::readFile(const char *path,LPBYTE pFileBuf,DWORD size)//读文件，size为要读的数(0读取全部)，返回读取字节数，放到pFileBuf中
{
	if(pFileBuf==NULL) return 0;
	int fsize;
	ifstream fin(path,ios::binary);
	if(fin.fail()) return 0;
	fin.seekg(0,ios::end);
	fsize = fin.tellg();
	fin.seekg(0,ios::beg);
	if(size==0 || fsize<size)  size=fsize;
	fin.read((char *)pFileBuf,size);
	fin.close();
	return size;
}

int CPEinfo::isPe(const char* path)
{
	BYTE buf[PEHBUF_SIZE];//判断pe只读取前0x100字节就行
	if (readFile(path, (LPBYTE)buf, PEHBUF_SIZE) == 0)
		return -3;
	return isPe((LPBYTE)buf);
}

int CPEinfo::isPe(LPBYTE pFileBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE) return -1; //"MZ"
	PIMAGE_NT_HEADERS32 pNtHeader = getNtHeader(pFileBuf);
	if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) return -2;  //"PE\0\0"
	return pNtHeader->OptionalHeader.Magic; 
}

DWORD CPEinfo::toAlignment(DWORD num,DWORD align)
{
	DWORD r = num%align;
	num -= r;
	if(r!=0) num += align;
	return num;
}

PIMAGE_NT_HEADERS CPEinfo::getNtHeader(LPBYTE pFileBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	return (PIMAGE_NT_HEADERS32)(pFileBuf + pDosHeader->e_lfanew);
}

PIMAGE_FILE_HEADER CPEinfo::getFileHeader(LPBYTE pFileBuf)
{
	return &getNtHeader(pFileBuf)->FileHeader;
}

PIMAGE_OPTIONAL_HEADER CPEinfo::getOptionalHeader(LPBYTE pFileBuf)
{
	return &getNtHeader(pFileBuf)->OptionalHeader;
}

PIMAGE_DATA_DIRECTORY CPEinfo::getImageDataDirectory(LPBYTE pFileBuf) 
{
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pFileBuf);
	return pOptionalHeader->DataDirectory;
}

PIMAGE_SECTION_HEADER CPEinfo::getSectionHeader(LPBYTE pFileBuf)
{
	PIMAGE_NT_HEADERS pNtHeader = getNtHeader(pFileBuf);
	return (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));
}

PIMAGE_IMPORT_DESCRIPTOR CPEinfo::getImportDescriptor(LPBYTE pFileBuf, bool bMemAlign = true)
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = getImageDataDirectory(pFileBuf);
	DWORD rva =  pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD offset = bMemAlign ?  rva2faddr(pFileBuf, rva) : rva;
	return (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuf + offset);
}

DWORD CPEinfo::getPeMemSize(const char* path)
{
	BYTE buf[PEHBUF_SIZE];
	readFile(path, buf, PEHBUF_SIZE);
	return getPeMemSize(buf);
}

DWORD CPEinfo::getPeMemSize(LPBYTE pFileBuf)
{
	if (pFileBuf == NULL) return 0;
	if (isPe((LPBYTE)pFileBuf) <= 0) return 0;
	return getOptionalHeader(pFileBuf)->SizeOfImage;
}

DWORD CPEinfo::getOverlaySize(const char* path)
{
	BYTE buf[PEHBUF_SIZE];
	DWORD filesize;

	filesize = getFileSize(path);
	if (filesize == 0) return 0;
	readFile(path, buf, PEHBUF_SIZE);
	int res = isPe(buf);
	if (res > 0) return getOverlaySize(buf, filesize);
	return res;	
}

DWORD CPEinfo::getOverlaySize(LPBYTE pFileBuf, DWORD filesize)
{
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuf);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuf);
	WORD sec_num = pFileHeader->NumberOfSections;
	DWORD olaysize = filesize - (
		pSectionHeader[sec_num - 1].PointerToRawData +
		pSectionHeader[sec_num - 1].SizeOfRawData);
	return olaysize;
}

DWORD CPEinfo::readOverlay(const char* path, LPBYTE pOverlayBuf)
{
	if (pOverlayBuf == NULL) return 0;
	DWORD filesize = getFileSize(path);
	if (filesize == 0) return 0;
	LPBYTE pFileBuf = new BYTE[filesize];
	readFile(path, pFileBuf, filesize);
	int res = isPe(pFileBuf);
	if (res > 0)
	{
		res = readOverlay(pFileBuf, filesize, pOverlayBuf);
	}
	delete[] pFileBuf;
	return res;
}

DWORD CPEinfo::readOverlay(LPBYTE pFileBuf, DWORD filesize, LPBYTE pOverlayBuf)
{
	DWORD olaysize = getOverlaySize(pFileBuf, filesize);
	if (olaysize > 0) memcpy(pOverlayBuf, pFileBuf + filesize - olaysize, olaysize);
	return olaysize;
}

DWORD CPEinfo::addOverlay(const char* path, LPBYTE pOverlay, DWORD size)//附加数据，此处不再对齐了
{
	if (pOverlay == NULL) return 0;
	ofstream fout(path, ios::binary | ios::app);
	if (fout.fail()) return 0;
	fout.seekp(0, ios::end);
	fout.write((const char*)pOverlay, size);
	fout.close();
	return size;
}

DWORD CPEinfo::getOepRva(const char* path)
{
	BYTE buf[PEHBUF_SIZE];//判断pe只读取前0x100字节就行
	readFile(path, buf, PEHBUF_SIZE);
	return getOepRva(buf);
}

DWORD CPEinfo::getOepRva(LPBYTE pFileBuf)
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0;
	return getOptionalHeader(pFileBuf)->AddressOfEntryPoint;
}

DWORD CPEinfo::setOepRva(const char* path, DWORD rva)
{
	BYTE buf[PEHBUF_SIZE];
	int readsize = readFile(path, buf, PEHBUF_SIZE);
	if (readsize == 0) return 0;
	DWORD oldrva = setOepRva((LPBYTE)buf, rva);
	if (oldrva == 0) return 0;
	ofstream fout(path, ios::binary | ios::ate | ios::in);//ios::out则清空文件，ios::app每次写都是在最后，ios::ate可以用seekp
	fout.seekp(0, ios::beg);
	fout.write((const char*)buf, readsize);
	fout.close();
	return oldrva;
}

DWORD CPEinfo::setOepRva(LPBYTE pFileBuf, DWORD rva)//返回原来的rva
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0;
	DWORD* pRva = &getOptionalHeader(pFileBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRva;
	*pRva = rva;
	return oldrva;
}

DWORD CPEinfo::rva2faddr(const char* path, DWORD rva)
{
	BYTE buf[PEHBUF_SIZE];
	int size = readFile(path, buf, PEHBUF_SIZE);
	if (size == 0) return 0;
	return rva2faddr(buf, rva);
}

DWORD CPEinfo::rva2faddr(LPBYTE pFileBuf, DWORD rva)
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pFileBuf);
	if (rva <= pOptionalHeader -> SectionAlignment) return rva;//pe头部分
	DWORD rvaoff;//rva相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pFileBuf);
	WORD sec_num = getFileHeader(pFileBuf) -> NumberOfSections;
	for (int i = 0; i < sec_num; i++)
	{
		rvaoff = rva - pSecHeader[i].VirtualAddress;
		if (rvaoff >= 0 && rvaoff <= pSecHeader[i].Misc.VirtualSize)
		{
			return rvaoff + pSecHeader[i].PointerToRawData;
		}
	}
	return 0;
}

DWORD CPEinfo::faddr2rva(const char* path, DWORD faddr)
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) <= 0) return 0;
	return faddr2rva(buf, faddr);
}

DWORD CPEinfo::faddr2rva(LPBYTE pFileBuf, DWORD faddr)
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pFileBuf);
	if (faddr <= pOptionalHeader -> FileAlignment) return faddr;
	DWORD faddroff;//faddr相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pFileBuf);
	WORD sec_num = getFileHeader(pFileBuf)->NumberOfSections;
	for (int i = 0; i < sec_num; i++)
	{
		faddroff = faddr - pSecHeader[i].PointerToRawData;
		if (faddroff >= 0 && faddroff <= pSecHeader[i].SizeOfRawData)
		{
			return faddroff + pSecHeader[i].VirtualAddress;
		}
		i++;
	}
	return 0;
}
#ifdef _WIN64
DWORD CPEinfo::va2rva(const char* path, ULONGLONG va)
#else
DWORD CPEinfo::va2rva(const char* path, DWORD va)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2rva(buf, va);
}

#ifdef _WIN64
DWORD CPEinfo::va2rva(LPBYTE pFileBuf, ULONGLONG va)
#else
DWORD CPEinfo::va2rva(LPBYTE pFileBuf, DWORD va)
#endif
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0; 
	return va - getOptionalHeader(pFileBuf)->ImageBase;
}

#ifdef _WIN64
ULONGLONG CPEinfo::rva2va(const char* path, DWORD rva)
#else
DWORD CPEinfo::rva2va(const char* path, DWORD rva)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return rva2va(buf, rva);
}

#ifdef _WIN64
ULONGLONG CPEinfo::rva2va(LPBYTE pFileBuf, DWORD rva)
#else
DWORD CPEinfo::rva2va(LPBYTE pFileBuf, DWORD rva)
#endif
{
	if (pFileBuf == NULL) return 0;
	if (isPe(pFileBuf) <= 0) return 0;
	return rva + getOptionalHeader(pFileBuf)->ImageBase;
}

#ifdef _WIN64
ULONGLONG CPEinfo::faddr2va(char* path, DWORD faddr)
#else
DWORD CPEinfo::faddr2va(const char* path, DWORD faddr)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return faddr2va(buf, faddr);
}

#ifdef _WIN64
ULONGLONG CPEinfo::faddr2va(LPBYTE pFileBuf, DWORD faddr)
#else
DWORD CPEinfo::faddr2va(LPBYTE pFileBuf, DWORD faddr)
#endif
{
	if (pFileBuf == NULL) return 0;
	return rva2va(pFileBuf, faddr2rva(pFileBuf, faddr));
}

#ifdef _WIN64
DWORD CPEinfo::va2faddr(const char* path, ULONGLONG va)
#else
DWORD CPEinfo::va2faddr(const char* path, DWORD va)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2faddr(buf, va);
}
#ifdef _WIN64
DWORD CPEinfo::va2faddr(LPBYTE pFileBuf, ULONGLONG va)
#else
DWORD CPEinfo::va2faddr(LPBYTE pFileBuf, DWORD va)
#endif
{
	if (pFileBuf == NULL) return 0;
	return rva2faddr(pFileBuf, va2rva(pFileBuf, va));
}

DWORD CPEinfo::loadPeFile(const char* path,
	LPBYTE pFileBuf, DWORD* FileBufSize,
	bool bMemAlign,
	LPBYTE pOverlayBuf, DWORD* OverlayBufSize)//失败返回0，成功返回读取总字节数,FileBufSize=0自动确认
{
	if (pFileBuf == NULL) return 0;
	DWORD loadsize = 0;
	DWORD filesize = getFileSize(path);;
	LPBYTE buf = new BYTE[filesize];
	if (readFile(path, buf, 0) <= 0) return 0;
	if (isPe(buf) > 0)
	{
		PIMAGE_NT_HEADERS pNtHeader = getNtHeader(pFileBuf);
		PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pFileBuf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		DWORD last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		if (bMemAlign == false)
		{
			memcpy(pFileBuf, buf, filesize);
			if (FileBufSize != NULL) *FileBufSize = filesize;
			if (last_faddr < filesize)
			{
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else
		{
			memset(pFileBuf, 0, memsize);
			loadsize = memsize;
			memcpy(pFileBuf, buf, pNtHeader->OptionalHeader.SizeOfHeaders);//PE区段
			for (int i = 0; i < sec_num; i++)//赋值
			{
				memcpy(pFileBuf + pSecHeader[i].VirtualAddress,
					buf + pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);
			}
			if (last_faddr < filesize)//附加数据
			{
				memcpy(pOverlayBuf, buf + last_faddr, filesize - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
				loadsize += filesize - last_faddr;
			}
		}
		delete[] buf;
	}
	return loadsize;
}

DWORD CPEinfo::savePeFile(const char* path,
	LPBYTE pFileBuf, DWORD FileBufSize,
	bool isMemAlign,
	LPBYTE pOverlayBuf, DWORD OverlayBufSize)//失败返回0，成功返回写入总字节数
{
	if (pFileBuf == NULL) return 0;
	fstream fout;
	DWORD writesize = 0;
	fout.open(path, ios::in);//判断文件是否存在
	if (!fout.fail()) return 0;
	fout.close();
	fout.open(path, ios::out | ios::binary);
	if (isPe((LPBYTE)pFileBuf)<0) return 0;
	if (isMemAlign == false)
	{
		fout.write((const char*)pFileBuf, FileBufSize);
		writesize = FileBufSize;
	}
	else
	{
		
		DWORD last_peaddr;
		DWORD faddr;
		DWORD sectrva;
		DWORD sectsize;

		writesize = 0;
		PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuf);
		PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pFileBuf);
		PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pFileBuf);
		WORD sec_num = pFileHeader -> NumberOfSections;
		last_peaddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		fout.write((const char*)pFileBuf, pOptionalHeader -> SizeOfHeaders);//保存pe区
		writesize += pOptionalHeader->SizeOfHeaders;
		for (int i = 0; i < sec_num; i++)
		{
			sectrva = pSecHeader[i].VirtualAddress;
			sectsize = toAlignment(pSecHeader[i].SizeOfRawData, pOptionalHeader->FileAlignment);
			faddr = fout.tellp();//防止地址不对
			if (faddr > pSecHeader[i].PointerToRawData)
			{
				fout.seekp(pSecHeader[i].PointerToRawData);//防止重叠
			}

			else if (faddr < pSecHeader[i].PointerToRawData)//防止区段少
			{
				for (int j = faddr; j < pSecHeader[i].PointerToRawData; j++) fout.put(0);
			}
			fout.write((const char*)(pFileBuf + sectrva), sectsize);
			writesize += sectsize;
		}
	}
	if (pOverlayBuf != NULL && OverlayBufSize != 0)
	{
		fout.write((const char*)pOverlayBuf, OverlayBufSize);
		writesize += OverlayBufSize;
	}
	fout.close();
	return writesize;
}

/*Static end*/

/* constructors*/
CPEinfo::CPEinfo(const char* path, bool isMemAlign)
{
	CPEinfo();
	openPeFile(path, isMemAlign);
}

CPEinfo::CPEinfo(LPBYTE pFileBuf, DWORD filesize, bool isCopyMem, bool isMemAlign)
{
	CPEinfo();
	attachPeBuf(pFileBuf, filesize, isCopyMem, isMemAlign);
}
void CPEinfo::copy(const CPEinfo& pe, bool isCopyMem)//默认拷贝函数
{
	attachPeBuf(pe.getFileBuf(), pe.getFileBufSize(),
		isCopyMem, pe.isMemAlign(),
		pe.getOverlayBuf(), pe.getOverlayBufSize());
	strcpy(this->m_szFilePath, pe.m_szFilePath);
}
CPEinfo::CPEinfo(const CPEinfo &pe)
{
	copy(pe, true);
}

CPEinfo& CPEinfo::operator=(CPEinfo& pe32)
{
	copy(pe32, true);
	return *this;
}
/* constructors end*/

/*public functions*/
void CPEinfo::iniValue()
{
	m_bMemAlign = true;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
	m_bMemAlloc = true;//是否内存为此处分配的
		
	memset(m_szFilePath,0,MAX_PATH);
	m_pFileBuf=0;		//PE文件缓冲区
	m_dwFileBufSize=0;	//PE文件缓存区大小
	m_pOverlayBuf=NULL;	//PE附加数据
	m_dwOverlayBufSize=0; //PE附加数据大小
}

DWORD CPEinfo::openPeFile(const char* path, bool bMemAlign)//暂时不用内存映射，不用loadPeFile函数，若是filealign节省一次内存载入	
{
	//释放之前资源
	closePeFile();
	m_bMemAlign = bMemAlign;

	DWORD filesize = getFileSize(path);
	DWORD loadsize = 0;
	LPBYTE pFileBuf = new BYTE[filesize];
	if (readFile(path, (LPBYTE)pFileBuf, 0) <= 0) return -3;
	if (CPEinfo::isPe((LPBYTE)pFileBuf) > 0)
	{
		DWORD last_faddr;
		auto pNtHeader = CPEinfo::getNtHeader(pFileBuf);
		auto pSecHeader = CPEinfo::getSectionHeader(pFileBuf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;

		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		if (bMemAlign == false)
		{
			m_pFileBuf = pFileBuf;
			m_dwFileBufSize = last_faddr;
			m_dwOverlayBufSize = filesize - last_faddr;
			if (last_faddr < filesize)
			{
				m_pOverlayBuf = pFileBuf + last_faddr;
				m_dwOverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else
		{
			loadsize = memsize;
			m_dwFileBufSize = memsize;
			m_pFileBuf = new BYTE[memsize];
			memset(m_pFileBuf, 0, memsize);
			memcpy(m_pFileBuf, pFileBuf, pNtHeader->OptionalHeader.SizeOfHeaders);
			for (WORD i = 0; i < sec_num; i++)//赋值
			{
				memcpy(m_pFileBuf + pSecHeader[i].VirtualAddress,
					pFileBuf + pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);

			}
			if (last_faddr < filesize)
			{
				m_dwOverlayBufSize = filesize - last_faddr;
				m_pOverlayBuf = new BYTE[m_dwOverlayBufSize];
				memcpy(m_pOverlayBuf, pFileBuf + last_faddr, m_dwOverlayBufSize);
				loadsize += m_dwOverlayBufSize;
			}
			delete[] pFileBuf;
		}
	}
	return loadsize;
}

int CPEinfo::attachPeBuf(LPBYTE pFileBuf,DWORD dwFileBufSize,
						bool bCopyMem, bool bMemAlign,
						LPBYTE pOverlayBuf, DWORD dwOverLayBufSize)
{
	if(pFileBuf==NULL) return 0;
	m_bMemAlloc= bCopyMem;
	m_bMemAlign= bMemAlign;
	closePeFile();
	int res=isPe((LPBYTE)pFileBuf);
	if(res>0)
	{
		if(bCopyMem)
		{
			m_pFileBuf=new BYTE[dwFileBufSize];
			m_pOverlayBuf=new BYTE[dwOverLayBufSize];
			memcpy(m_pFileBuf,pFileBuf,dwFileBufSize);
			if(pOverlayBuf!=NULL) memcpy(m_pOverlayBuf,pOverlayBuf,dwOverLayBufSize);
		}
		else
		{
			m_pFileBuf = pFileBuf;
			m_pOverlayBuf = pOverlayBuf;
		}
		m_dwFileBufSize = dwFileBufSize;
		m_dwOverlayBufSize = dwOverLayBufSize;
	}
	return res;
}

void CPEinfo::closePeFile()								
{
	if(m_szFilePath[0]!=0) memset(m_szFilePath,0,MAX_PATH);
	if (m_bMemAlloc == true && m_pFileBuf != NULL) delete[] m_pFileBuf;
	if (m_bMemAlloc == true && m_pOverlayBuf != NULL) delete[] m_pOverlayBuf;
	m_pFileBuf = NULL;
	m_dwFileBufSize = 0;
	m_pOverlayBuf = NULL;
	m_dwOverlayBufSize = 0;
}

DWORD CPEinfo::savePeFile(const char* path)
{
	return savePeFile(path, m_pFileBuf, m_dwFileBufSize,
		m_bMemAlign,
		m_pOverlayBuf, m_dwOverlayBufSize);
}

int CPEinfo::isPe()
{
	return CPEinfo::isPe(m_pFileBuf);
}

DWORD CPEinfo::getOepRva()
{
	return getOepRva(m_pFileBuf);
}
DWORD CPEinfo::setOepRva(DWORD rva)
{
	return setOepRva(m_pFileBuf, rva);
}

DWORD CPEinfo::rva2faddr(DWORD rva) const
{
	return rva2faddr(m_pFileBuf, rva);
}

DWORD CPEinfo::faddr2rva(DWORD faddr) const
{
	return faddr2rva(m_pFileBuf, faddr);

}
#ifdef _WIN64
DWORD CPEinfo::va2rva(ULONGLONG va) const
{
	return va2rva(m_pFileBuf, va);
}

ULONGLONG CPEinfo::rva2va(DWORD rva) const
{
	return rva2va(m_pFileBuf, rva);
}

ULONGLONG CPEinfo::faddr2va(faddr) const
{
	return faddr2va(m_pFileBuf, faddr);
}

DWORD CPEinfo::va2faddr(ULONGLONG va) const
{
	return va2faddr(m_pFileBuf, va);
}
#else
DWORD CPEinfo::va2rva(DWORD va) const
{
	return va2rva(m_pFileBuf, va);
}

DWORD CPEinfo::rva2va(DWORD rva) const
{
	return rva2va(m_pFileBuf, rva);
}

DWORD CPEinfo::faddr2va(DWORD faddr) const
{
	return faddr2va(m_pFileBuf, faddr);
}

DWORD CPEinfo::va2faddr(DWORD va) const
{
	return va2faddr(m_pFileBuf, va);
}
#endif

bool CPEinfo::isMemAlign() const
{
	return m_bMemAlign;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
}

bool CPEinfo::isMemAlloc() const
{
	return m_bMemAlloc;//是否内存为此处分配的
}

const char* const CPEinfo::getFilePath() const
{
	return m_szFilePath;
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

PIMAGE_NT_HEADERS CPEinfo::getNtHeader()
{
	return getNtHeader(m_pFileBuf);
}
PIMAGE_FILE_HEADER CPEinfo::getFileHeader()
{
	return getFileHeader(m_pFileBuf);
}
PIMAGE_OPTIONAL_HEADER CPEinfo::getOptionalHeader()
{
	return getOptionalHeader(m_pFileBuf);
}
PIMAGE_DATA_DIRECTORY CPEinfo::getImageDataDirectory()
{
	return getImageDataDirectory(m_pFileBuf);
}
PIMAGE_SECTION_HEADER CPEinfo::getSectionHeader()
{
	return getSectionHeader(m_pFileBuf);
}
PIMAGE_IMPORT_DESCRIPTOR CPEinfo::getImportDescriptor()
{
	return getImportDescriptor(m_pFileBuf, m_bMemAlign);
}
/*public functions end*/