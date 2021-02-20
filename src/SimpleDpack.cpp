
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
	LPBYTE srcBuf = m_packpe.getPeBuf() + srcrva;//指向缓存区
	DWORD srcsize = m_packpe.getOptionalHeader()->SizeOfCode + sizeof(DLZMA_HEADER);//压缩大小
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
	GetModuleInformation(GetCurrentProcess(), m_hShell, &meminfo, sizeof(MODULEINFO));
	m_shellpe.attachPeBuf((LPBYTE)m_hShell, meminfo.SizeOfImage, true);  // 复制到新缓存区，防止virtual protect无法修改
	m_pShellIndex = (PDPACK_SHELL_INDEX)(m_shellpe.getPeBuf() + 
		(size_t)GetProcAddress(m_hShell, "g_dpackShellIndex") - (size_t)m_hShell); 
	return meminfo.SizeOfImage;
}

void CSimpleDpack::initShellIndex(DWORD shellSize)
{
	//g_dpackShellIndex OrgIndex赋值
	m_pShellIndex->OrgIndex.OepRva = m_packpe.getOepRva();
	m_pShellIndex->OrgIndex.ImageBase = m_packpe.getOptionalHeader()->ImageBase;
	auto pPackpeImpEntry = &m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	m_pShellIndex->OrgIndex.ImportRva = pPackpeImpEntry->VirtualAddress;
	m_pShellIndex->OrgIndex.ImportSize = pPackpeImpEntry->Size;

	//g_dpackShellIndex  SectionIndex赋值
	DWORD trva = m_packpe.getOptionalHeader()->SizeOfImage + shellSize;
	for (int i = 0; i < m_dpackSectNum; i++) //将压缩区段信息存取shell
	{
		m_pShellIndex->SectionIndex[i].OrgRva = m_dpackTmpbuf[i].OrgRva;
		m_pShellIndex->SectionIndex[i].OrgSize = m_dpackTmpbuf[i].OrgMemSize;
		m_pShellIndex->SectionIndex[i].PackedRva = trva;
		m_pShellIndex->SectionIndex[i].PackedSize = m_dpackTmpbuf[i].PackedSize;
		trva += CPEinfo::toAlignment(m_dpackTmpbuf[i].PackedSize, m_packpe.getOptionalHeader()->SectionAlignment);
	}
	m_pShellIndex->SectionNum = m_dpackSectNum;
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

void CSimpleDpack::adjustPackpeHeaders()
{
	// 设置被加壳程序的信息, oep, reloc, iat
	if (m_pShellIndex == NULL) return;
	auto packpeImageSize = m_packpe.getOptionalHeader()->SizeOfImage;
	m_packpe.setOepRva((size_t)m_pShellIndex->DpackOepFunc - 
		m_packpe.getOptionalHeader()->ImageBase); // 之前已经reloc过了，变成了正确的va了
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + packpeImageSize,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size };
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + packpeImageSize,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].Size };
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
	adjustShellReloc(m_packpe.getOptionalHeader()->SizeOfImage); // reloc调整后全局变量g_dpackShellIndex的oep也变成之后
	adjustShellIat(m_packpe.getOptionalHeader()->SizeOfImage);
	initShellIndex(shellsize); // 初始化dpack shell index，一定要在reloc之后, 因为reloc后这里的地址也变了
	adjustPackpeHeaders();   // 调整要pack的pe头
	LPBYTE pBuf = new BYTE[shellsize];
	memcpy(pBuf, m_shellpe.getPeBuf(), shellsize);
	addDpackTmpbufEntry(pBuf, shellsize); // 将改好的dll shell放入tmp buf
	return packsize + shellsize;
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
	char sect_name[8] = ".dpack";
	auto pSecHeader = m_packpe.getSectionHeader();
	DWORD sect_faddr = (DWORD)((LPBYTE)pSecHeader - m_packpe.getPeBuf());
	WORD  oldsect_num = m_packpe.getFileHeader()->NumberOfSections;
	DWORD oldhsize = m_packpe.getOptionalHeader()->SizeOfHeaders; //原来pe头大小
	DWORD newhsize = oldhsize;
	DWORD file_align = m_packpe.getOptionalHeader()->FileAlignment;
	DWORD mem_align = m_packpe.getOptionalHeader()->SectionAlignment;
	auto pOldSect = new IMAGE_SECTION_HEADER[oldsect_num];//不改变原始数据
	auto pNewSect = new IMAGE_SECTION_HEADER[m_dpackSectNum];

	//pe头文件上大小修正
	if (oldhsize - sect_faddr < (oldsect_num + m_dpackSectNum) * sizeof(IMAGE_SECTION_HEADER))
	{
		newhsize = CPEinfo::toAlignment(
			(oldsect_num + m_dpackSectNum) * sizeof(IMAGE_SECTION_HEADER)+ sect_faddr, file_align);
		m_packpe.getOptionalHeader()->SizeOfHeaders = newhsize;
	}
	
	//旧区段头
	memcpy(pOldSect, pSecHeader, sizeof(IMAGE_SECTION_HEADER) * oldsect_num);
	DWORD tfaddr = pSecHeader->PointerToRawData - oldhsize + newhsize;
	for (WORD i = 0, j = 0; i < oldsect_num; i++)
	{
		auto ptSect = &pOldSect[i];
		ptSect->PointerToRawData = tfaddr;//修改因有些区段文件上空的偏移
		while (m_dpackTmpbuf[j].OrgRva == 0 && j < m_dpackSectNum - 1) { j++; }//跳过不是原来区段pack的
		if (ptSect->VirtualAddress + ptSect->Misc.VirtualSize <= m_dpackTmpbuf[j].OrgRva
			|| m_dpackTmpbuf[j].OrgRva == 0 || j > m_dpackSectNum - 1)//不是空区段
		{
			tfaddr += CPEinfo::toAlignment(ptSect->SizeOfRawData, file_align);
		}
		else
		{
			ptSect->SizeOfRawData = 0;
			j++;
		}
	}
	
	//新增区段头
	DWORD trva = pSecHeader[oldsect_num - 1].VirtualAddress
		+ CPEinfo::toAlignment(pSecHeader[oldsect_num - 1].Misc.VirtualSize, 
			m_packpe.getOptionalHeader()->SectionAlignment);
	auto ptSect = &pNewSect[0];//第一个放shell code
	memset(ptSect, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(ptSect->Name, sect_name, 8);
	ptSect->SizeOfRawData = m_dpackTmpbuf[m_dpackSectNum - 1].PackedSize;
	ptSect->PointerToRawData = tfaddr;
	ptSect->VirtualAddress = trva;
	ptSect->Misc.VirtualSize = m_dpackTmpbuf[m_dpackSectNum - 1].PackedSize;
	ptSect->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	trva += CPEinfo::toAlignment(ptSect->Misc.VirtualSize, mem_align);
	tfaddr += CPEinfo::toAlignment(ptSect->SizeOfRawData, file_align);
	for (int i = 1; i < m_dpackSectNum; i++)
	{
		ptSect = &pNewSect[i];
		memset(ptSect, 0, sizeof(IMAGE_SECTION_HEADER));

		memcpy(ptSect->Name, sect_name, 8);
		ptSect->SizeOfRawData = m_dpackTmpbuf[i - 1].PackedSize;
		ptSect->PointerToRawData = tfaddr;
		ptSect->VirtualAddress = trva;
		ptSect->Misc.VirtualSize = m_dpackTmpbuf[i - 1].PackedSize;
		ptSect->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
		trva += CPEinfo::toAlignment(ptSect->Misc.VirtualSize, mem_align);
		tfaddr += CPEinfo::toAlignment(ptSect->SizeOfRawData, file_align);
	}
	
	//新缓冲区复制
	DWORD savesize = tfaddr;
	LPBYTE pNewBuf = new BYTE[savesize];
	memset(pNewBuf, 0, tfaddr);//清零
	m_packpe.getOptionalHeader()->SizeOfImage = trva;//pe头的其他信息修改
	m_packpe.getFileHeader()->NumberOfSections = oldsect_num + m_dpackSectNum;
	m_packpe.getFileHeader()->Characteristics |= IMAGE_FILE_RELOCS_STRIPPED; //禁止基址随机化
	memcpy(pNewBuf, m_packpe.getPeBuf(), oldhsize);//旧pe头
	memcpy(pNewBuf + sect_faddr, pOldSect, sizeof(IMAGE_SECTION_HEADER) * oldsect_num);//旧区段头
	memcpy(pNewBuf + sect_faddr + oldsect_num * sizeof(IMAGE_SECTION_HEADER), pNewSect,
		m_dpackSectNum * sizeof(IMAGE_SECTION_HEADER));//新区段头
	for (int i = 0; i < oldsect_num; i++)//旧区段数据
	{
		ptSect = &pOldSect[i];
		if (ptSect->SizeOfRawData != 0)
		{
			memcpy(pNewBuf + pOldSect[i].PointerToRawData,
				m_packpe.getPeBuf() + ptSect->VirtualAddress, ptSect->SizeOfRawData);
		}
	}
	memcpy(pNewBuf + pNewSect[0].PointerToRawData, //注意区段数据与索引的对应关系
		m_dpackTmpbuf[m_dpackSectNum - 1].PackedBuf, m_dpackTmpbuf[m_dpackSectNum - 1].PackedSize);
	for (int i = 1; i < m_dpackSectNum; i++)//新区段数据
	{
		memcpy(pNewBuf + pNewSect[i].PointerToRawData,
			m_dpackTmpbuf[i - 1].PackedBuf, m_dpackTmpbuf[i - 1].PackedSize);
	}
	
	//写入文件
	savesize = CPEinfo::savePeFile(path, pNewBuf, savesize, false, m_packpe.getOverlayBuf(), m_packpe.getOverlayBufSize());
	//清理
	delete[] pNewSect;
	delete[] pOldSect;
	delete[] pNewBuf;
	return savesize;
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