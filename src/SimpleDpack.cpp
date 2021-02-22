
#include "SimpleDpack.hpp"
#include "lzma\lzmalib.h"

/*static functions*/
DWORD CSimpleDpack::dlzmaPack(LPBYTE* dst, LPBYTE src, DWORD lzmasize, double maxmul)
{
	if (src == NULL) return 0;
	for (double m = 1; m <= maxmul; m += 0.1)
	{
		if (*dst != NULL)
		{
			delete[] dst;
			lzmasize = (DWORD)(m * (double)lzmasize);//防止分配缓存区空间过小
		}
		*dst = new BYTE[lzmasize];
		DWORD res = ::dlzmaPack(*dst, src, lzmasize);
		if (res > 0) return res;
	}
	return 0;
}
/*static functions end*/

/*Constructor*/
void CSimpleDpack::iniValue()
{
	memset(m_strFilePath, 0, MAX_PATH);
	memset(m_packSectMap, 0, sizeof(m_packSectMap));
	m_hShell = NULL;
	m_pShellIndex = NULL;
	m_dpackSectNum = 0;
}

CSimpleDpack::CSimpleDpack(char* path)
{
	iniValue();
	loadPeFile(path);
}

void CSimpleDpack::release()
{
	initDpackTmpbuf();
	m_packpe.closePeFile();
	m_shellpe.closePeFile();
	if (m_hShell != NULL) FreeLibrary((HMODULE)m_hShell);
}
/*Constructor end*/

/*private functions*/
WORD CSimpleDpack::initDpackTmpbuf()
{
	WORD oldDpackSectNum = m_dpackSectNum;
	if (m_dpackSectNum != 0)
	{
		for (int i = 0; i < m_dpackSectNum; i++)
			if (m_dpackTmpbuf[i].PackedBuf != NULL && m_dpackTmpbuf[i].PackedSize != 0)
				delete[] m_dpackTmpbuf[i].PackedBuf;
	}
	m_dpackSectNum = 0;
	memset(m_dpackTmpbuf, 0, sizeof(m_dpackTmpbuf));
	return oldDpackSectNum;
}

WORD CSimpleDpack::addDpackTmpbufEntry(LPBYTE PackedBuf, DWORD PackedSize, DWORD OrgRva, DWORD OrgMemSize)
{
	m_dpackTmpbuf[m_dpackSectNum].PackedBuf = PackedBuf;
	m_dpackTmpbuf[m_dpackSectNum].PackedSize = PackedSize;
	m_dpackTmpbuf[m_dpackSectNum].OrgRva = OrgRva;
	m_dpackTmpbuf[m_dpackSectNum].OrgMemSize = OrgMemSize;
	m_dpackSectNum++;
	return m_dpackSectNum;
}

DWORD CSimpleDpack::packSection(int type)	//处理各区段
{
	LPBYTE dstBuf = NULL;
	DWORD allsize = 0;

	//pack各区段,暂时只压缩代码段
	m_dpackSectNum = 0;
	DWORD srcrva = m_packpe.getOptionalHeader()->BaseOfCode;//获取code段rva
	m_packSectMap[m_packpe.findRvaSectIdx(srcrva)] = True;
	LPBYTE srcBuf = m_packpe.getPeBuf() + srcrva;//指向缓存区
	DWORD srcsize = m_packpe.getOptionalHeader()->SizeOfCode
		+ sizeof(DLZMA_HEADER);//压缩大小
	DWORD dstsize = dlzmaPack(&dstBuf, srcBuf, srcsize);//压缩
	if (dstsize == 0) return 0;
	addDpackTmpbufEntry(dstBuf, dstsize, srcrva, srcsize);
	allsize = dstsize;
	
	return allsize;
}

DWORD CSimpleDpack::loadShellDll(const char* dllpath)	//处理外壳,若其他操作系统要重写
{
	m_hShell = LoadLibrary(dllpath);
	MODULEINFO meminfo = { 0 };//读取dpack shell 代码
	GetModuleInformation(GetCurrentProcess(), 
		m_hShell, &meminfo, sizeof(MODULEINFO));
	m_shellpe.attachPeBuf((LPBYTE)m_hShell, 
		meminfo.SizeOfImage, true);  // 复制到新缓存区，防止virtual protect无法修改
	m_pShellIndex = (PDPACK_SHELL_INDEX)(m_shellpe.getPeBuf() + 
		(size_t)GetProcAddress(m_hShell, "g_dpackShellIndex") - (size_t)m_hShell); 
	return meminfo.SizeOfImage;
}

DWORD CSimpleDpack::adjustShellReloc(DWORD shellBaseRva)//设置dll重定位信息，返回个数
{
	size_t oldImageBase = m_hShell ? (size_t)m_hShell : m_shellpe.getOptionalHeader()->ImageBase;
	return m_shellpe.shiftReloc(oldImageBase, m_packpe.getOptionalHeader()->ImageBase, shellBaseRva);
}

DWORD CSimpleDpack::adjustShellIat(DWORD shellBaseRva) // 调整shellcode中的iat
{
	return m_shellpe.shiftOft(shellBaseRva);
}

void CSimpleDpack::initShellIndex(DWORD shellEndRva)
{
	//g_dpackShellIndex OrgIndex赋值
	m_pShellIndex->OrgIndex.OepRva = m_packpe.getOepRva();
	m_pShellIndex->OrgIndex.ImageBase = m_packpe.getOptionalHeader()->ImageBase;
	auto pPackpeImpEntry = &m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	m_pShellIndex->OrgIndex.ImportRva = pPackpeImpEntry->VirtualAddress;
	m_pShellIndex->OrgIndex.ImportSize = pPackpeImpEntry->Size;

	//g_dpackShellIndex  SectionIndex赋值
	DWORD trva = m_packpe.getOptionalHeader()->SizeOfImage + shellEndRva;
	for (int i = 0; i < m_dpackSectNum; i++) //将压缩区段信息存取shell
	{
		m_pShellIndex->SectionIndex[i].OrgRva = m_dpackTmpbuf[i].OrgRva;
		m_pShellIndex->SectionIndex[i].OrgSize = m_dpackTmpbuf[i].OrgMemSize;
		m_pShellIndex->SectionIndex[i].PackedRva = trva;
		m_pShellIndex->SectionIndex[i].PackedSize = m_dpackTmpbuf[i].PackedSize;
		trva += CPEinfo::toAlign(m_dpackTmpbuf[i].PackedSize, m_packpe.getOptionalHeader()->SectionAlignment);
	}
	m_pShellIndex->SectionNum = m_dpackSectNum;
}

DWORD CSimpleDpack::makeAppendBuf(DWORD shellStartRva, DWORD shellEndRva, DWORD shellBaseRva)
{
	DWORD bufsize = shellEndRva - shellStartRva ;
	LPBYTE pBuf = new BYTE[bufsize];
	memcpy(pBuf, m_shellpe.getPeBuf() + shellStartRva, bufsize);
	
#if 1
	// 清空export表,  可能会报毒
	auto pExpDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		                      (size_t)m_shellpe.getExportDirectory()
		                    - (size_t)m_shellpe.getPeBuf() + (size_t)pBuf - shellStartRva);
	LPBYTE pbtmp = pBuf + pExpDirectory->Name - shellStartRva;
	while (*pbtmp != 0) *pbtmp++ = 0; 
	DWORD n = pExpDirectory->NumberOfFunctions;
	PDWORD  pdwtmp = (PDWORD)(pBuf + pExpDirectory->AddressOfFunctions - shellStartRva);
	for (int i = 0; i < n; i++) *pdwtmp++ = 0;
	n = pExpDirectory->NumberOfNames;
	pdwtmp = (PDWORD)(pBuf + pExpDirectory->AddressOfNames - shellStartRva);
	for (int i = 0; i < n; i++) 
	{
		pbtmp = *pdwtmp - shellStartRva + pBuf;
		while (*pbtmp != 0) *pbtmp++ = 0;
		*pdwtmp++ = 0;
	}
	memset(pExpDirectory, 0, sizeof(IMAGE_EXPORT_DIRECTORY));
#endif

	// 将改好的dll shell放入tmp buf
	addDpackTmpbufEntry(pBuf, bufsize, shellBaseRva + shellStartRva, bufsize);
	return shellStartRva;
}

void CSimpleDpack::adjustPackpeHeaders(DWORD offset)
{
	// 设置被加壳程序的信息, oep, reloc, iat
	if (m_pShellIndex == NULL) return;
	auto packpeImageSize = m_packpe.getOptionalHeader()->SizeOfImage;
	// m_pShellIndex->DpackOepFunc 之前已经reloc过了，变成了正确的va了(shelldll是release版)
	m_packpe.setOepRva((size_t)m_pShellIndex->DpackOepFunc -
		m_packpe.getOptionalHeader()->ImageBase + offset);
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + packpeImageSize + offset,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size };
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + packpeImageSize + offset,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].Size };
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0,0 };

	// pe 属性设置
	m_packpe.getFileHeader()->Characteristics |= IMAGE_FILE_RELOCS_STRIPPED; //禁止基址随机化
}

/*private functions end*/

/*public functions*/
DWORD CSimpleDpack::loadPeFile(const char* path)//加载pe文件，返回isPE()值
{
	DWORD res = m_packpe.openPeFile(path);
	return res;
}

DWORD CSimpleDpack::packPe(const char* dllpath, int type)//加壳，失败返回0，成功返回pack数据大小
{
	if (m_packpe.getPeBuf() == NULL) return 0;
	initDpackTmpbuf(); // 初始化pack buf
	DWORD packsize = packSection(type); // pack各区段
	DWORD shellsize = loadShellDll(dllpath); // 载入dll shellcode
	
	DWORD packpeImgSize = m_packpe.getOptionalHeader()->SizeOfImage;
	DWORD shellStartRva = m_shellpe.getSectionHeader()[0].VirtualAddress;
	DWORD shellEndtRva = m_shellpe.getSectionHeader()[3].VirtualAddress; // rsrc
	
	adjustShellReloc(packpeImgSize); // reloc调整后全局变量g_dpackShellIndex的oep也变成之后
	adjustShellIat(packpeImgSize);
	initShellIndex(shellEndtRva); // 初始化dpack shell index，一定要在reloc之后, 因为reloc后这里的地址也变了
	makeAppendBuf(shellStartRva, shellEndtRva, packpeImgSize);
	adjustPackpeHeaders(0);   // 调整要pack的pe头
	return packsize + shellEndtRva - shellStartRva;
}

DWORD CSimpleDpack::unpackPe(int type)//脱壳，其他同上（暂时不实现）
{
	return 0;
}

DWORD CSimpleDpack::savePe(const char* path)//失败返回0，成功返回文件大小
{
	/*
		pack区域放到后面，由于内存有对齐问题，只允许pack一整个区段
		先改pe头，再分配空间，支持若原来pe fileHeader段不够，添加段
		将区段头与区段分开考虑
	*/
	// dpack头初始化
	IMAGE_SECTION_HEADER dpackSect = {0};
	strcpy((char*)dpackSect.Name, ".dpack");
	dpackSect.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	dpackSect.VirtualAddress = m_dpackTmpbuf[m_dpackSectNum - 1].OrgRva;
	
	// dpack buf
	DWORD dpackBufSize = 0;
	for (int i = 0; i < m_dpackSectNum; i++) dpackBufSize += m_dpackTmpbuf[i].PackedSize;
	LPBYTE pdpackBuf = new BYTE[dpackBufSize];
	LPBYTE pCurBuf = pdpackBuf;
	memcpy(pdpackBuf, m_dpackTmpbuf[m_dpackSectNum - 1].PackedBuf, 
		m_dpackTmpbuf[m_dpackSectNum - 1].PackedSize); // 壳代码
	pCurBuf += m_dpackTmpbuf[m_dpackSectNum - 1].PackedSize;
	for (int i = 0; i < m_dpackSectNum -1 ; i++)
	{
		memcpy(pCurBuf, m_dpackTmpbuf[i].PackedBuf,
			m_dpackTmpbuf[i].PackedSize); // 壳代码
		pCurBuf += m_dpackTmpbuf[i].PackedSize;
	}
	// 写入pe
	m_packpe.appendSection(dpackSect, pdpackBuf, dpackBufSize);
	delete[] pdpackBuf;
	return m_packpe.savePeFile(path);
}

CPEinfo* CSimpleDpack::getExepe()
{
	return &m_packpe;
}

 const char* CSimpleDpack::getFilePath() const
 {
	 return m_strFilePath;
 }
 /*public functions end*/