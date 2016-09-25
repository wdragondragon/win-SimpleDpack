#include <Windows.h>
#include "lzma\lzmalib.h"
#include "dpackType.h"
#ifndef _DPACKCODE_H
#define _DPACKCODE_H
/*
	dpack encoder
*/
DWORD dlzmaPack(LPBYTE dst,LPBYTE src,DWORD size);
#endif