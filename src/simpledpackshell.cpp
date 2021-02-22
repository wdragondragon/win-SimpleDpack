#include "simpledpackshell.h"
void dpackStart();
extern "C" {
	DPACK_API DPACK_SHELL_INDEX g_dpackShellIndex = { (PVOID)dpackStart,0 };//顺便初始化壳oep
}
#ifdef _WIN64
ULONGLONG g_orgOep
#else
DWORD g_orgOep;
#endif

__declspec(naked) void BeforeUnpack()
{

}

__declspec(naked) void AfterUnpack()
{

}

#ifdef _WIN32
__declspec(naked) void JmpOrgOep()
{
	__asm
	{
		push g_orgOep;
		ret;
	}
}
#endif

__declspec(naked) void dpackStart()//此函数中不要有局部变量
{

	BeforeUnpack();
	MallocAll(NULL);
	UnpackAll(NULL);
	g_orgOep = g_dpackShellIndex.OrgIndex.ImageBase + g_dpackShellIndex.OrgIndex.OepRva;
	LoadOrigionIat(NULL);
	AfterUnpack();
	JmpOrgOep();
}

void MallocAll(PVOID arg)
{
	MEMORY_BASIC_INFORMATION mi = { 0 };
	HANDLE hProcess = GetCurrentProcess();
	HMODULE imagebase = GetModuleHandle(NULL);
	for (int i = 0; i < g_dpackShellIndex.SectionNum; i++)
	{
		if (g_dpackShellIndex.SectionIndex[i].OrgRva == 0) continue;
		LPBYTE tVa = (LPBYTE)imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva;
		DWORD tSize = g_dpackShellIndex.SectionIndex[i].OrgSize;
		VirtualQueryEx(hProcess, tVa, &mi, tSize);
		if(mi.State == MEM_FREE)
		{
			DWORD flProtect = PAGE_EXECUTE_READWRITE;
			switch (g_dpackShellIndex.SectionIndex[i].Characteristics)
			{
			    case IMAGE_SCN_MEM_EXECUTE:
					flProtect = PAGE_EXECUTE;
					break;
				case IMAGE_SCN_MEM_READ:
					flProtect = PAGE_READONLY;
					break;
				case IMAGE_SCN_MEM_WRITE:
					flProtect = PAGE_READWRITE;
					break;
			}
			if(!VirtualAllocEx(hProcess, tVa, tSize, MEM_COMMIT, flProtect))
			{
				MessageBox(NULL,"Alloc memory failed", "error", NULL);
				ExitProcess(1);
			}
		}
	}   
}

void UnpackAll(PVOID arg)
{
	DWORD oldProtect;
#ifdef _WIN64
	ULONGLONG imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#else
	DWORD imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#endif
	for(int i=0; i<g_dpackShellIndex.SectionNum; i++)
	{
		switch(g_dpackShellIndex.SectionIndex[i].DpackSectionType)
		{
		case  DPACK_SECTION_RAW:
		{
			if (g_dpackShellIndex.SectionIndex[i].OrgSize == 0) continue;
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((void*)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				(void*)(imagebase + g_dpackShellIndex.SectionIndex[i].DpackRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize);
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				oldProtect, &oldProtect);
			break;
		}
		case DPACK_SECTION_DLZMA:
		{
			LPBYTE buf = new BYTE[g_dpackShellIndex.SectionIndex[i].OrgSize];
			if (!dlzmaUnpack(buf, 
				(LPBYTE)(g_dpackShellIndex.SectionIndex[i].DpackRva + imagebase),
				g_dpackShellIndex.SectionIndex[i].DpackSize))
			{
				MessageBox(0, "unpack failed", "error", 0);
				ExitProcess(1);
			}
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((void*)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				buf, g_dpackShellIndex.SectionIndex[i].OrgSize);
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				oldProtect, &oldProtect);
			delete[] buf;
			break;
		}
		default:
			break;
		}
	}
}

void LoadOrigionIat(PVOID arg)  // 因为将iat改为了壳的，所以要还原原来的iat
{
	DWORD i,j;
	DWORD dll_num = g_dpackShellIndex.OrgIndex.ImportSize
		/sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD item_num=0;//一个dll中导入函数的个数,不包括全0的项
	DWORD oldProtect;
	HMODULE tHomule;//临时加载dll的句柄
	LPBYTE tName;//临时存放名字
#ifdef _WIN64
	ULONGLONG tVa;//临时存放虚拟地址
	ULONGLONG imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#else
	DWORD tVa;//临时存放虚拟地址
	DWORD imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#endif
	PIMAGE_IMPORT_DESCRIPTOR pImport=(PIMAGE_IMPORT_DESCRIPTOR)(imagebase+
		g_dpackShellIndex.OrgIndex.ImportRva);//指向第一个dll
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
				tName=(LPBYTE)pFuncName->Name;
#ifdef _WIN64
				tVa = (ULONGLONG)GetProcAddress(tHomule, (LPCSTR)tName);
#else
				tVa = (DWORD)GetProcAddress(tHomule, (LPCSTR)tName);
#endif
			}
			else
			{
				//如果此参数是一个序数值，它必须在一个字的低字节，高字节必须为0。
#ifdef _WIN64			
				tVa = (ULONGLONG)GetProcAddress(tHomule,(LPCSTR)(poThunk[j].u1.Ordinal & 0x0000ffff));
#else
				tVa = (DWORD)GetProcAddress(tHomule, (LPCSTR)(poThunk[j].u1.Ordinal & 0x0000ffff));
#endif
			}
			if (tVa == NULL)
			{
				MessageBox(NULL, "IAT load error!", "error", NULL);
				ExitProcess(1);
			}
			pfThunk[j].u1.Function = tVa;//注意间接寻址
		}
		VirtualProtect((LPVOID)(pfThunk),item_num * sizeof(IMAGE_THUNK_DATA),
				oldProtect,&oldProtect);
	}
}