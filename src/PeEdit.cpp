#include "PEedit.hpp"
#include <fstream>
using namespace std;

/* static functions */
DWORD CPEedit::addOverlay(const char* path, LPBYTE pOverlay, DWORD size)//附加数据，此处不再对齐了
{
	if (pOverlay == NULL) return 0;
	ofstream fout(path, ios::binary | ios::app);
	if (fout.fail()) return 0;
	fout.seekp(0, ios::end);
	fout.write((const char*)pOverlay, size);
	fout.close();
	return size;
}

DWORD CPEedit::setOepRva(const char* path, DWORD rva)
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

DWORD CPEedit::setOepRva(LPBYTE pPeBuf, DWORD rva)//返回原来的rva
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	DWORD* pRva = &getOptionalHeader(pPeBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRva;
	*pRva = rva;
	return oldrva;
}

DWORD CPEedit::shiftReloc(LPBYTE pPeBuf, ULONGLONG oldImageBase, ULONGLONG newImageBase, DWORD offset, bool bMemAlign)
{
	//修复重定位,其实此处pShellBuf为hShell副本
	DWORD all_num = 0;
	DWORD sumsize = 0;
	auto pRelocEntry = &getImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	while (sumsize < pRelocEntry->Size)
	{
		auto pBaseRelocation = (PIMAGE_BASE_RELOCATION)(pPeBuf  + sumsize + 
			(bMemAlign ? pRelocEntry->VirtualAddress :
				rva2faddr(pPeBuf, pRelocEntry->VirtualAddress)));
		auto pRelocOffset = (PRELOCOFFSET)
			((LPBYTE)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseRelocation->SizeOfBlock - 
			sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		for (int i = 0; i < item_num; i++)
		{
			if (pRelocOffset[i].offset == 0) continue;
			DWORD toffset = pRelocOffset[i].offset + pBaseRelocation->VirtualAddress;
			if (!bMemAlign) toffset = rva2faddr(pPeBuf, toffset);

			// 新的重定位地址 = 重定位后的地址(VA)-加载时的镜像基址(hModule VA) + 新的镜像基址(VA) + 新代码基址RVA（前面用于存放压缩的代码）
			// 由于讲dll附加在后面，需要在dll shell中的重定位加上偏移修正
#ifdef _WIN64
			*(ULONGLONG)(pPeBuf + toffset) += newImageBase - oldImageBase + offset; //重定向每一项地址
#else
			//printf("%08lX -> ", *(PDWORD)(pPeBuf + toffset));
			*(PDWORD)(pPeBuf + toffset) += newImageBase - oldImageBase + offset; //重定向每一项地址
			//printf("%08lX\n", *(PDWORD)(pPeBuf + toffset));
#endif
		}
		pBaseRelocation->VirtualAddress += offset; //重定向页表基址
		sumsize += sizeof(RELOCOFFSET) * item_num + sizeof(IMAGE_BASE_RELOCATION);
		all_num += item_num;
	}
	return all_num;
}

DWORD CPEedit::shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign)
{
	auto pImportEntry = &getImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD dll_num = pImportEntry->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD func_num = 0;//所有导入函数个数，不包括全0的项
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (pPeBuf +
		(bMemAlign ? pImportEntry->VirtualAddress : 
		rva2faddr(pPeBuf, pImportEntry->VirtualAddress)));//指向第一个dll
	for (int i = 0; i < dll_num; i++)
	{
		if (pImportDescriptor[i].OriginalFirstThunk == 0) continue;
		auto pThunk = (PIMAGE_THUNK_DATA)(pPeBuf + (bMemAlign ?
			pImportDescriptor[i].OriginalFirstThunk: 
			rva2faddr(pPeBuf, pImportDescriptor[i].OriginalFirstThunk)));
		DWORD item_num = 0;
		for (int j = 0; pThunk[j].u1.AddressOfData != 0; j++)
		{
			item_num++; //一个dll中导入函数的个数,不包括全0的项
			if ((pThunk[j].u1.Ordinal >> 31) != 0x1) //不是用序号
			{
				pThunk[j].u1.AddressOfData += offset;
			}
		}
		pImportDescriptor[i].OriginalFirstThunk += offset;
		pImportDescriptor[i].Name += offset;
		pImportDescriptor[i].FirstThunk += offset;
		func_num += item_num;
	}
	return func_num;
}

/* static functions end */

/* public funcitons*/
DWORD CPEedit::setOepRva(DWORD rva)
{
	return setOepRva(m_pPeBuf, rva);
}

DWORD  CPEedit::shiftReloc(ULONGLONG oldImageBase, ULONGLONG newImageBase, DWORD offset)
{
	return shiftReloc(m_pPeBuf, oldImageBase, newImageBase, offset, m_bMemAlign);
}

DWORD  CPEedit::shiftOft(DWORD offset)
{
	return shiftOft(m_pPeBuf, offset, m_bMemAlign);
}

/* public funcitons end*/