#include <Windows.h>
#include "dpackType.h"
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	PDLZMA_HEADER pdlzmah = (PDLZMA_HEADER)pSrcBuf;
	size_t dstSize = pdlzmah->RawDataSize;//release版不赋初值会出错，由于debug将其赋值为cccccccc很大的数
	LzmaUncompress(pDstBuf, &dstSize,//此处必须赋最大值
		          pSrcBuf + sizeof(DLZMA_HEADER), &srcSize,
		          pdlzmah->LzmaProps, LZMA_PROPS_SIZE);
	return dstSize;
}