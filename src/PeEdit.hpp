#include "PeInfo.hpp"
#ifndef _PEEDIT_H
#define _PEEDIT_H
class CPEedit :public CPEinfo
{
public:
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	static DWORD setOepRva(const char* path, DWORD rva);
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD rva);//返回原来的rvas
	static DWORD shiftReloc(LPBYTE pPeBuf, ULONGLONG oldImageBase, ULONGLONG newImageBase, DWORD offset, bool bMemAlign = true); // 将reloc记录以及reloc指向的地址进行基址变换
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true); // 将IAT进行基址变换, 返回修改iat数量

public:
	DWORD setOepRva(DWORD rva);
	DWORD shiftReloc(ULONGLONG oldImageBase, ULONGLONG newImageBase, DWORD offset);
	DWORD shiftOft(DWORD offset);
};
#endif
