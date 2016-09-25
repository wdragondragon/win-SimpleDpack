#include "simpledpackshell32.h"
void dpackStart();
DPACK_HDADER32 g_stcShellHDADER32={(DWORD)dpackStart,0};//顺便初始化壳oep
DWORD oepva;
__declspec(naked) void dpackStart()//此函数中不要有局部变量
{
	_asm
	{
		pushad
		mov eax,eax ;仅仅为了方便debug定位
		mov eax,eax ;
		mov eax,eax ;
	}
	unpackAll();
	oepva=g_stcShellHDADER32.origin_index.dwImageBase+g_stcShellHDADER32.origin_index.dwOepRva;
	fixOrigionIat();
	_asm
	{
		mov ebx,ebx
		mov ebx,ebx
		mov ebx,ebx
		popad
		push oepva
		ret
	}
}
void unpackAll()
{
	_asm
	{
		mov ecx,ecx
		mov ecx,ecx
		mov ecx,ecx
	}
	int i;
	DWORD imagebase=g_stcShellHDADER32.origin_index.dwImageBase;
	DWORD res;
	DWORD oldProtect;
	LPBYTE tBuf;
	for(i=0;i<g_stcShellHDADER32.trans_num;i++)
	{
		tBuf=new BYTE[g_stcShellHDADER32.trans_index[i].dwOrigion_size];
		res=dlzmaUnPack(tBuf,(LPBYTE)(g_stcShellHDADER32.trans_index[i].dwTrans_rva+imagebase),
			g_stcShellHDADER32.trans_index[i].dwTrans_size);
		if(res==0) 
		{
			MessageBox(0,"unpack failed","error",0);
			ExitProcess(1);
		}
		VirtualProtect((void *)(imagebase+g_stcShellHDADER32.trans_index[i].dwOrigion_rva),
						g_stcShellHDADER32.trans_index[i].dwOrigion_size,
						PAGE_EXECUTE_READWRITE ,&oldProtect);
		memcpy((void *)(imagebase+g_stcShellHDADER32.trans_index[i].dwOrigion_rva),
				tBuf,g_stcShellHDADER32.trans_index[i].dwOrigion_size);
		VirtualProtect((void *)(imagebase+g_stcShellHDADER32.trans_index[i].dwOrigion_rva),
						g_stcShellHDADER32.trans_index[i].dwOrigion_size,
						oldProtect,NULL);
		delete[] tBuf;
	}
	
}
void fixOrigionIat()
{
	_asm
	{
		mov edx,edx
		mov edx,edx
		mov edx,edx
	}
	DWORD i,j;
	DWORD imagebase=g_stcShellHDADER32.origin_index.dwImageBase;
	DWORD dll_num=g_stcShellHDADER32.origin_index.dwImportSize
		/sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD item_num=0;//一个dll中导入函数的个数,不包括全0的项
	DWORD oldProtect;
	HMODULE tHomule;//临时加载dll的句柄
	LPBYTE tName;//临时存放名字
	DWORD tVa;//临时存放虚拟地址
	PIMAGE_IMPORT_DESCRIPTOR pImport=(PIMAGE_IMPORT_DESCRIPTOR)(imagebase+
		g_stcShellHDADER32.origin_index.dwImportRva);//指向第一个dll
	PIMAGE_THUNK_DATA pfThunk;//ft
	PIMAGE_THUNK_DATA poThunk;//oft
	PIMAGE_IMPORT_BY_NAME pFuncName;
	for(i=0;i<dll_num;i++)
	{
		if(pImport[i].OriginalFirstThunk==0) continue;
		tName=(LPBYTE)(imagebase+pImport[i].Name);
		tHomule=LoadLibrary((LPCSTR)tName);
		pfThunk=(PIMAGE_THUNK_DATA)(imagebase+pImport[i].FirstThunk);
		poThunk=(PIMAGE_THUNK_DATA)(imagebase+pImport[i].OriginalFirstThunk);
		for(j=0;poThunk[j].u1.AddressOfData!=0;j++){}//注意个数。。。
		item_num=j;

		VirtualProtect((LPVOID)(pfThunk),item_num * sizeof(IMAGE_THUNK_DATA),
						PAGE_EXECUTE_READWRITE,&oldProtect);//注意指针位置
		for(j=0;j<item_num;j++)
		{
			if((poThunk[j].u1.Ordinal >>31) != 0x1) //不是用序号
			{
				pFuncName=(PIMAGE_IMPORT_BY_NAME)(imagebase+poThunk[j].u1.AddressOfData);
				tName=pFuncName->Name;
				tVa=(DWORD)GetProcAddress(tHomule,(LPCSTR)tName);
			}
			else
			{
				//如果此参数是一个序数值，它必须在一个字的底字节，高字节必须为0。
				tVa=(DWORD)GetProcAddress(tHomule,(LPCSTR)(poThunk[j].u1.Ordinal & 0x0000ffff));
			}
			pfThunk[j].u1.Function=tVa;//注意间接寻址
		}
		VirtualProtect((LPVOID)(pfThunk),item_num * sizeof(IMAGE_THUNK_DATA),
				oldProtect,NULL);
	}
}