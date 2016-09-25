#include "SimpleDpack32.hpp"
extern "C"
{
#include <psapi.h>
}
/*Constructor*/
CSimpleDpack32::CSimpleDpack32(char *path)
{
	iniValue();
	loadPeFile(path);
}
void CSimpleDpack32::release()
{
	iniDpackIndex();
	m_pe32.releaseAllBuf();
	m_pe32.closePeFile();
	m_shellpe32.releaseAllBuf();
	if(m_hShell!=NULL) FreeLibrary((HMODULE)m_hShell);
}
/*Constructor end*/

/*Private*/
WORD CSimpleDpack32::iniDpackIndex()
{
	WORD oldDpackSectNum=m_dpackSectNum;
	if(m_dpackSectNum!=0)
		for(int i=0;i<m_dpackSectNum;i++)
			if(m_dpackIndex[i].packBuf!=NULL && m_dpackIndex[i].packBufSize!=0)
				delete[] m_dpackIndex[i].packBuf;
	m_dpackSectNum=0;
	memset(m_dpackIndex,0,sizeof(m_dpackIndex));
	return oldDpackSectNum;
}
WORD CSimpleDpack32::addDpackIndex(LPBYTE packBuf,DWORD packBufSize,DWORD srcRva,DWORD srcMemSize)
{
	m_dpackIndex[m_dpackSectNum].packBuf=packBuf;
	m_dpackIndex[m_dpackSectNum].packBufSize=packBufSize;
	m_dpackIndex[m_dpackSectNum].srcRva=srcRva;
	m_dpackIndex[m_dpackSectNum].srcMemSize=srcMemSize;
	m_dpackSectNum++;
	return m_dpackSectNum;
}
DWORD CSimpleDpack32::setShellReloc(LPBYTE pShellBuf, DWORD hShell,DWORD shellBaseRva)//设置dll重定位信息，返回个数
{
	//修复重定位,其实此处pShellBuf为hShell副本
	int i;
	DWORD all_num=0;
	DWORD item_num=0;//一个reloc区段中的地址数量
	DWORD sumsize=0;
	DWORD trva;
	LPBYTE pSrcRbuf=(LPBYTE)hShell+m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	LPBYTE pDstRbuf=(LPBYTE)pShellBuf+m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocsize=m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	PIMAGE_BASE_RELOCATION pSrcReloc;
	PIMAGE_BASE_RELOCATION pDstReloc;
	PRELOCOFFSET pSrcRoffset;
	PRELOCOFFSET pDstRoffset;
	while(sumsize<relocsize)
	{
		pSrcReloc=(PIMAGE_BASE_RELOCATION)(pSrcRbuf+sumsize);
		pDstReloc=(PIMAGE_BASE_RELOCATION)(pDstRbuf+sumsize);
		item_num=(pSrcReloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
		sumsize+=sizeof(IMAGE_BASE_RELOCATION);
		pSrcRoffset=(PRELOCOFFSET)((DWORD)pSrcReloc+sizeof(IMAGE_BASE_RELOCATION));
		pDstRoffset=(PRELOCOFFSET)((DWORD)pDstReloc+sizeof(IMAGE_BASE_RELOCATION));//注意指针类型
		for(i=0;i<item_num;i++)
		{
			if(pSrcRoffset[i].offset==0) continue;
			trva=pSrcRoffset[i].offset+pSrcReloc->VirtualAddress;
			//新重定位地址=重定位后地址-加载时的镜像基址+新的镜像基址+代码基址(PE文件镜像大小)
			*(PDWORD)((DWORD)pShellBuf+trva)=*(PDWORD)((DWORD)hShell+trva)-hShell
				+*m_pe32.m_pe32Index.pdwImageBase+shellBaseRva;//重定向每一项地址
		}
		pDstReloc->VirtualAddress+=shellBaseRva;//重定向页表基址
		sumsize+=sizeof(WORD)*item_num;
		all_num+=item_num;
	}
	return all_num;
}
DWORD CSimpleDpack32::setShellIat(LPBYTE pShellBuf, DWORD hShell,DWORD shellBaseRva)
{
	DWORD i,j;
	DWORD dll_num=m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
		/sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD item_num=0;//一个dll中导入函数的个数,不包括全0的项
	DWORD func_num=0;//所有导入函数个数，不包括全0的项
	PIMAGE_IMPORT_DESCRIPTOR pImport=(PIMAGE_IMPORT_DESCRIPTOR)(pShellBuf+
		m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);//指向第一个dll
	PIMAGE_THUNK_DATA pThunk;
	PIMAGE_IMPORT_BY_NAME pFuncName;//此处不用改，顺序排列，name不是指针
	for(i=0;i<dll_num;i++)
	{
		if(pImport[i].OriginalFirstThunk==0) continue;
		pThunk=(PIMAGE_THUNK_DATA)(pShellBuf+pImport[i].OriginalFirstThunk);
		item_num=0;
		for(j=0;pThunk[j].u1.AddressOfData!=0;j++)
		{
			item_num++;
			if((pThunk[j].u1.Ordinal >>31) != 0x1) //不是用序号
			{
				pFuncName=(PIMAGE_IMPORT_BY_NAME)(pShellBuf+pThunk[j].u1.AddressOfData);
				pThunk[j].u1.AddressOfData+=shellBaseRva;
			}
		}
		memcpy(pShellBuf+pImport[i].FirstThunk,
				pShellBuf+pImport[i].OriginalFirstThunk,
				item_num * sizeof(IMAGE_THUNK_DATA));//由于first thunk 在 dll 加载后已经被替换成iat了，应该用oft还原
		pImport[i].OriginalFirstThunk+=shellBaseRva;
		pImport[i].Name+=shellBaseRva;
		pImport[i].FirstThunk+=shellBaseRva;
		func_num+=item_num;
	}
	return func_num;
}
DWORD CSimpleDpack32::sectProc(int type)	//处理各区段
{
	/*
		由于内存有对齐问题，只允许pack一整个区段
	*/
	LPBYTE dstBuf=NULL;
	LPBYTE srcBuf=NULL;
	DWORD srcrva;
	DWORD srcsize;
	DWORD dstsize;
	DWORD allsize=0;

	//pack各区段,暂时只压缩代码段
	m_dpackSectNum=0;
	srcrva=*(m_pe32.m_pe32Index.pdwCodeBaseRva);//获取code段rva
	srcBuf=m_pe32.getFileBuf()+srcrva;//指向缓存区
	srcsize=*(m_pe32.m_pe32Index.pdwCodeSize)+sizeof(DLZMA_HEADER);//压缩大小
	dstsize=dlzmaPack(&dstBuf,srcBuf,srcsize);//压缩
	if(dstsize==0) return 0;
	addDpackIndex(dstBuf,dstsize,srcrva,srcsize);
	allsize=dstsize;
	return allsize;
}
DWORD CSimpleDpack32::shelldllProc(int type,char *dllpath)	//处理外壳,若其他操作系统要重写
{
	LPBYTE dstBuf=NULL;
	//加载dpack shell dll
	HMODULE hShell=LoadLibrary(dllpath);
	if(hShell==NULL) return 0;
	PDPACK_HDADER32 p_sh32=(PDPACK_HDADER32)GetProcAddress(hShell,"g_stcShellHDADER32");
	if(p_sh32==NULL) return 0;
	m_hShell=(DWORD)hShell;
	m_gShellHeader32=p_sh32;
	//dpack shell头赋值
	p_sh32->origin_index.dwOepRva=m_pe32.getOepRva();
	p_sh32->origin_index.dwImageBase=*m_pe32.m_pe32Index.pdwImageBase;
	p_sh32->origin_index.dwExportRva=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	p_sh32->origin_index.dwExportSize=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
									//Size/sizeof(IMAGE_EXPORT_DIRECTORY);
	p_sh32->origin_index.dwImportRva=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	p_sh32->origin_index.dwImportSize=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
									//Size/sizeof(IMAGE_IMPORT_DESCRIPTOR);
	p_sh32->origin_index.dwResourceRva=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	p_sh32->origin_index.dwResourceSize=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
									//Size/sizeof(IMAGE_RESOURCE_DIRECTORY);
	p_sh32->origin_index.dwRelocRva=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	p_sh32->origin_index.dwRelocSize=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
									//Size/sizeof(IMAGE_BASE_RELOCATION);
	p_sh32->origin_index.dwTlsRva=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	p_sh32->origin_index.dwTlsSize=m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].Size;
									//Size/sizeof(IMAGE_TLS_DIRECTORY32);
	MODULEINFO minfo={0};//读取dpack shell 代码
	GetModuleInformation(GetCurrentProcess(), hShell, &minfo, sizeof(MODULEINFO));
	DWORD trva=*m_pe32.m_pe32Index.pdwImageSize+minfo.SizeOfImage;
	for(int i=0;i<m_dpackSectNum;i++)//将压缩区段信息存取shell
	{
		p_sh32->trans_index[i].dwOrigion_rva=m_dpackIndex[i].srcRva;
		p_sh32->trans_index[i].dwOrigion_size=m_dpackIndex[i].srcMemSize;
		p_sh32->trans_index[i].dwTrans_rva=trva;
		p_sh32->trans_index[i].dwTrans_size=m_dpackIndex[i].packBufSize;
		trva+=CPEinfo::toAlignment(m_dpackIndex[i].packBufSize,*m_pe32.m_pe32Index.pdwMemAlign);
	}
	p_sh32->trans_num=m_dpackSectNum;

	//复制dpack shell 代码
	dstBuf=new BYTE[minfo.SizeOfImage];
	memcpy(dstBuf,hShell,minfo.SizeOfImage);
	m_shellpe32.attachPeBuf(dstBuf,minfo.SizeOfImage,false);
	//设置dpack shell重定位信息
	setShellReloc(dstBuf,(DWORD)hShell,*m_pe32.m_pe32Index.pdwImageSize);
	//设置dpack shell iat信息
	setShellIat(dstBuf,(DWORD)hShell,*m_pe32.m_pe32Index.pdwImageSize);
	//记录shell 指针
	addDpackIndex(dstBuf,minfo.SizeOfImage);
	//设置被加壳程序的信息
	m_pe32.setOepRva(p_sh32->dpackOepVa-(DWORD)hShell+ *m_pe32.m_pe32Index.pdwImageSize);//oep
	m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=
		m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
		+*m_pe32.m_pe32Index.pdwImageSize;
	m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=
		m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;//reloc
	m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=
		m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		+*m_pe32.m_pe32Index.pdwImageSize;
	m_pe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=
		m_shellpe32.m_pe32Index.pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;//导入表
	return minfo.SizeOfImage;
}
/*Private end*/

/*Public*/
void CSimpleDpack32::iniValue()
{	
	m_hShell=NULL;
	m_gShellHeader32=NULL;
	m_dpackSectNum=0;
}
DWORD CSimpleDpack32::loadPeFile(char *path)//加载pe文件，返回isPE()值
{
	DWORD res= m_pe32.openPeFile(path);
	m_pe32.getPeIndex();
	return res;
}
DWORD CSimpleDpack32::packPe(int type,char *dllpath)//加壳，失败返回0，成功返回pack数据大小
{
	if(m_pe32.getFileBuf()==NULL) return 0;
	DWORD allsize=0,tmpsize;
	iniDpackIndex();
	tmpsize=sectProc(type);
	if(tmpsize==0) return 0;
	allsize+=tmpsize;
	tmpsize=shelldllProc(type,dllpath);
	if(tmpsize==0) return 0;
	return allsize;
}
DWORD CSimpleDpack32::unpackPe(int type)//脱壳，其他同上（暂时不实现）
{
	return 0;
}
DWORD CSimpleDpack32::savePe(char *path)//失败返回0，成功返回文件大小
{
	/*
		pack区域放到后面，由于内存有对齐问题，只允许pack一整个区段
		先改pe头，再分配空间，支持若原来pe fileHeader段不够，添加段
		将区段头与区段分开考虑
	*/
	char sect_name[8]=".dpack";
	WORD i,j;
	DWORD tfaddr=0;
	DWORD savesize=0;
	DWORD trva=0;
	DWORD sect_faddr=(DWORD)m_pe32.m_pe32Index.pSectionHeader-(DWORD)m_pe32.getFileBuf();
	WORD  oldsect_num=*m_pe32.m_pe32Index.pwSectionNum;
	DWORD oldhsize=*m_pe32.m_pe32Index.pdwHeaderSize;//原来pe头文件上大小
	DWORD newhsize=oldhsize;
	PIMAGE_SECTION_HEADER ptSect;
	PIMAGE_SECTION_HEADER pOldSect=new IMAGE_SECTION_HEADER[oldsect_num];//不改变原始数据
	PIMAGE_SECTION_HEADER pNewSect=new IMAGE_SECTION_HEADER[m_dpackSectNum];
	LPBYTE pNewBuf;
	
	//pe头文件上大小修正
	if(oldhsize-sect_faddr < (oldsect_num+m_dpackSectNum) *sizeof(IMAGE_SECTION_HEADER))
	{
		newhsize=CPEinfo::toAlignment((oldsect_num+m_dpackSectNum) *sizeof(IMAGE_SECTION_HEADER)
										+sect_faddr,*m_pe32.m_pe32Index.pdwFileAlign);
		*m_pe32.m_pe32Index.pdwHeaderSize=newhsize;
	}
	//旧区段头
	memcpy(pOldSect,m_pe32.m_pe32Index.pSectionHeader,sizeof(IMAGE_SECTION_HEADER) * oldsect_num);
	tfaddr=m_pe32.m_pe32Index.pSectionHeader->PointerToRawData-oldhsize+newhsize;
	for(i=0,j=0;i < oldsect_num;i++)
	{
		ptSect=&pOldSect[i];
		ptSect->PointerToRawData=tfaddr;//修改因有些区段文件上空的偏移
		while(m_dpackIndex[j].srcRva==0 && j<m_dpackSectNum-1){j++;}//跳过不是原来区段pack的
		if(ptSect->VirtualAddress + ptSect->Misc.VirtualSize <= m_dpackIndex[j].srcRva 
			|| m_dpackIndex[j].srcRva==0 || j>m_dpackSectNum-1)//不是空区段
		{
			tfaddr+=CPEinfo::toAlignment(ptSect->SizeOfRawData,*m_pe32.m_pe32Index.pdwFileAlign);
		}
		else
		{
			ptSect->SizeOfRawData=0;
			j++;
		}
	}
	//新增区段头
	trva=m_pe32.m_pe32Index.pSectionHeader[oldsect_num-1].VirtualAddress
		+CPEinfo::toAlignment(m_pe32.m_pe32Index.pSectionHeader[oldsect_num-1].Misc.VirtualSize,
								*m_pe32.m_pe32Index.pdwMemAlign);
	ptSect=&pNewSect[0];//第一个放shell code
	memset(ptSect,0,sizeof(IMAGE_SECTION_HEADER));	
	memcpy(ptSect->Name,sect_name,8);
	ptSect->SizeOfRawData=m_dpackIndex[m_dpackSectNum-1].packBufSize;
	ptSect->PointerToRawData=tfaddr;
	ptSect->VirtualAddress=trva;
	ptSect->Misc.VirtualSize=m_dpackIndex[m_dpackSectNum-1].packBufSize;
	ptSect->Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |IMAGE_SCN_MEM_EXECUTE;
	trva+=CPEinfo::toAlignment(ptSect->Misc.VirtualSize,*m_pe32.m_pe32Index.pdwMemAlign);
	tfaddr+=CPEinfo::toAlignment(ptSect->SizeOfRawData,*m_pe32.m_pe32Index.pdwFileAlign);
	for(i=1;i<m_dpackSectNum;i++)
	{
		ptSect=&pNewSect[i];
		memset(ptSect,0,sizeof(IMAGE_SECTION_HEADER));
		
		memcpy(ptSect->Name,sect_name,8);
		ptSect->SizeOfRawData=m_dpackIndex[i-1].packBufSize;
		ptSect->PointerToRawData=tfaddr;
		ptSect->VirtualAddress=trva;
		ptSect->Misc.VirtualSize=m_dpackIndex[i-1].packBufSize;
		ptSect->Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |IMAGE_SCN_MEM_EXECUTE;
		trva+=CPEinfo::toAlignment(	ptSect->Misc.VirtualSize,*m_pe32.m_pe32Index.pdwMemAlign);
		tfaddr+=CPEinfo::toAlignment(ptSect->SizeOfRawData,*m_pe32.m_pe32Index.pdwFileAlign);
	}
	//新缓冲区复制
	savesize=tfaddr;
	pNewBuf=new BYTE[savesize];
	memset(pNewBuf,0,tfaddr);//清零
	*m_pe32.m_pe32Index.pdwImageSize=trva;//pe头的其他信息修改
	*m_pe32.m_pe32Index.pwSectionNum=oldsect_num+m_dpackSectNum;
	m_pe32.m_pe32Index.pNtHeader->FileHeader.Characteristics |=
		IMAGE_FILE_RELOCS_STRIPPED; //禁止基址随机化
	memcpy(pNewBuf,m_pe32.getFileBuf(),oldhsize);//旧pe头
	memcpy(pNewBuf+sect_faddr,pOldSect,sizeof(IMAGE_SECTION_HEADER) * oldsect_num);//旧区段头
	memcpy(pNewBuf+sect_faddr+oldsect_num *sizeof(IMAGE_SECTION_HEADER),pNewSect,
			m_dpackSectNum *sizeof(IMAGE_SECTION_HEADER));//新区段头
	for(i=0;i<oldsect_num;i++)//旧区段数据
	{
		ptSect=&pOldSect[i];
		if(ptSect->SizeOfRawData!=0)
		{
			memcpy(pNewBuf+pOldSect[i].PointerToRawData,
				m_pe32.getFileBuf()+ptSect->VirtualAddress,ptSect->SizeOfRawData);
		}
	}
	memcpy(pNewBuf+pNewSect[0].PointerToRawData,
		m_dpackIndex[m_dpackSectNum-1].packBuf,m_dpackIndex[m_dpackSectNum-1].packBufSize);//注意区段数据与索引的对应关系
	for(i=1;i<m_dpackSectNum;i++)//新区段数据
	{
		memcpy(pNewBuf+pNewSect[i].PointerToRawData,
			m_dpackIndex[i-1].packBuf,m_dpackIndex[i-1].packBufSize);
	}
	//写入文件
	savesize=CPEinfo32::savePeFile(path,pNewBuf,savesize,false,m_pe32.getOverlayBuf(),m_pe32.getOverlayBufSize());
	//清理
	delete[] pNewSect;
	delete[] pOldSect;
	delete[] pNewBuf;
	return savesize;
}
CPEinfo32* CSimpleDpack32::getPe()
{
	return &m_pe32;
}
/*Public end*/