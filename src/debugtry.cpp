#include "debugtry.h"
#include "PeInfo.hpp"
#include "SimpleDpack.hpp"
#include "capstone-3.0.4-win32\capstone.h"
#include <iostream>
#ifdef _DEBUGTRY
using namespace std;
class A
{
public: void print()
	{
		cout<<"A"<<endl;
	}
};
class B :public A
{
public: virtual void print()
	{
		cout<<"B"<<endl;
	}
};
class C :public B
{
public:void print()
	   {
		   cout<<"C"<<endl;
	   }

};
int dbg_cvirtfunc()
{ 
	C c;
	B *b=&c;
	A *a=&c;
	a->print();
	b->print();
	return 0;
}
int dbg_opcode2asm(void)//≤‚ ‘µ˜”√capstoneø‚
 {
  char *CODE="\x55\x48\x8b\x05\xb8\x13\x00\x00";
  csh handle;
  cs_insn *insn;
  size_t count;
 
  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
      return -1;
  count = cs_disasm(handle, (const uint8_t*)CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
  if (count > 0) {
      size_t j;
      for (j = 0; j < count; j++) {
          printf("0x%llx  %s    %s\n", insn[j].address,insn[j].mnemonic,insn[j].op_str);
      }
 
      cs_free(insn, count);
  } else
      printf("ERROR: Failed to disassemble given code!\n");
 
  cs_close(&handle);
 
     return 0;
 }
int dbg_lzma()//≤‚ ‘lzmaÀ„∑®
{
	char *words="§≥§≥§œ£¨LZMA§Œ§ø§¿§∑§´§…§¶§´£°";
	//char *words="1234";
	char word_compressed[100];
	char word_decompressed[100];
	unsigned int srclen;
	unsigned int deslen;
	unsigned int proplen;
	unsigned char outprop[5];
	
	printf("%s \n",words);
	srclen=strlen(words)+1;
	LzmaCompress((unsigned char *)word_compressed,&deslen,
				 (unsigned char *)words,srclen,
				 (unsigned char *)outprop,&proplen,
				  -1,0,-1,-1,-1,-1,-1);
	srclen=deslen;
	LzmaUncompress((unsigned char *)word_decompressed,&deslen,
		           (unsigned char *)word_compressed,&srclen,
				  (unsigned char *)outprop,proplen);
	printf("%s \n",word_decompressed);
	return 0;
}
int dbg_dlzma()
{	
	char *words="§≥§≥§œ£¨LZMA§Œ§ø§¿§∑§´§…§¶§´£°";
	//char *words="1234533334444";
	char buf[0x100],buf2[0x100];
	printf("%d\n",strlen(words)+1);
	memset(buf2,0,sizeof(0x100));
	printf("%s \n",words);
	int c;
	c=sizeof(DLZMA_HEADER);
	PDLZMA_HEADER pdlzmah=(PDLZMA_HEADER)buf;
	c=dlzmaPack((LPBYTE)buf,(LPBYTE)words,strlen(words)+1);
	printf("c=%d,pdlzmah->dwDataSize=%d,pdlzmah->dwRawDataSize=%d\n",c,pdlzmah->dwDataSize,pdlzmah->dwRawDataSize);
	c=dlzmaUnPack((LPBYTE)buf2,(LPBYTE)buf,pdlzmah->dwDataSize);
	printf("%s \n",buf2);
	//int destlen,size=pdlzmah->dwDataSize;
	//c=LzmaUncompress((unsigned char *)buf2,(size_t *)&destlen,
	//			   (unsigned char *)(buf+sizeof(DLZMA_HEADER)),(size_t *)&size,
	//			   (unsigned char *)&pdlzmah->outProps[0],LZMA_PROPS_SIZE);
	//printf("%d\n",c);
	//printf("%s \n",buf2);
	return 0;
}
int dbg_lzmauncompress()//lzmauncompress.libø‚≤‚ ‘
{
	char word_compressed[100]="\x00\x18\x8c\x82\xb6\xc1\x0c\x2f\xcb\x00\xcc";
	char word_decompressed[100];
	unsigned int srclen=10;
	unsigned int deslen;
	unsigned int proplen=5;
	unsigned char outprop[6]="\x5d\x00\x00\x00\x01";
	LzmaUncompress((unsigned char *)word_decompressed,&deslen,
		           (unsigned char *)word_compressed,&srclen,
				  (unsigned char *)outprop,proplen);
	printf("%s \n",word_decompressed);//1234
	return 1;
}
int dbg_rvaf()
{
	char *path="d:\\1.exe";
	CPEinfo::isPe("D:\\1.EXE");
	int c=CPEinfo::getOepRva("D:\\1.exe");
	c=CPEinfo::getFileSize("D:\\1.EXE");
	c=CPEinfo::rva2faddr(path,0x136);
	c=CPEinfo::faddr2rva(path,0x200000);
	c=CPEinfo::va2faddr(path,0x601e00);
	c=CPEinfo::faddr2va(path,0x200000);
	int a[42];
	int const *p=a;
	//p[2]=3;
	return 0;
}
int dbg_overlay()
{
	char *path="d:\\overlay.exe";
	PBYTE buf=new BYTE[0x100000];
	int c=CPEinfo::getOverlaySize(path);
	c=CPEinfo::readOverlay(path,buf);
	delete[] buf;
	DWORD oldrva=CPEinfo::setOepRva(path,300);
	c=CPEinfo::getOepRva(path);
	char *path2="d:\\ooxx.exe";
	char *str="write in overlay!";
	CPEinfo::addOverlay(path2,(LPBYTE)str,strlen(str)+1);
	return 0;
}
int dbg_savePe()
{
	char *inpath="d:\\ooxx.exe";
	char *outpath="d:\\ooxx2.exe";
	CPEinfo pe1(inpath,true);
	CPEinfo pe2(pe1);
	CPEinfo pe3;
	pe3=pe2;
	pe3.savePeFile(outpath);
	return 0;
}
int dbg_dpack()
{
	char *path="d:\\ooxx.exe";
	char *path2="d:\\oooxxx.exe";
	CSimpleDpack dpack(path);
	dpack.packPe();
	dpack.savePe(path2);
	return 0;
}
int main(int argc,char *argv[])
{
	printf("%d %s\n",argc,argv[0]);

	//dbg_dpack();
	//dbg_lzma();
	//dbg_dlzma();
	//dbg_savePe();
	//dbg_overlay();
	//dbg_cvirtfunc();
	//dbg_rvaf();
	//dbg_lzmauncompress();
}
#endif