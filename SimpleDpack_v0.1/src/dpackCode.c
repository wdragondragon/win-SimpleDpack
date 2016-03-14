#include <Windows.h>
#include "dpackCode.h"
DWORD dlzmaPack(LPBYTE dst,LPBYTE src,DWORD size)
{
	DWORD destlen;//此处不能复制，0才是压缩全部，返回到destlen
	DWORD proplen;
	PDLZMA_HEADER pdlzmah=(PDLZMA_HEADER)dst;
	
	LzmaCompress((unsigned char *)(dst+sizeof(DLZMA_HEADER)),(size_t *)&destlen,
				 (unsigned char *)src,(size_t)size,
				 (unsigned char *)(pdlzmah->outProps),(size_t *)&proplen,
				    -1,0,-1,-1,-1,-1,-1);
	pdlzmah->dwRawDataSize=size;
	pdlzmah->dwDataSize=destlen;
	return destlen;
}