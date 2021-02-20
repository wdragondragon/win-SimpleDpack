#include <Windows.h>
#include "dpackType.h"
DWORD dlzmaUnpack(LPBYTE dst, LPBYTE src, DWORD size)
{
	PDLZMA_HEADER pdlzmah = (PDLZMA_HEADER)src;
	DWORD destlen = pdlzmah->RawDataSize;//release版不赋初值会出错，由于debug将其赋值为cccccccc很大的数
	LzmaUncompress((unsigned char*)dst, (size_t*)&destlen,//此处必须赋最大值
		(const unsigned char*)((DWORD)src + sizeof(DLZMA_HEADER)), (size_t*)&size,
		(unsigned char*)&pdlzmah->LzmaProps[0], LZMA_PROPS_SIZE);
	return destlen;
}