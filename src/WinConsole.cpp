#include "WinConsole.h"
#include "debugtry.h"
#include <iostream>
#include <fstream>
using namespace std;
#ifndef _DEBUGTRY
/*
	ver0.1.1 Console
	simpledpack inpath [outpath]
*/
int main(int argc,char *argv[])
{
	cout<<"-----------------SimpleDpack ver0.1.1--------------------"<<endl;
	cout<<"[1]the initial demo version that can pack the pe32 exe file"<<endl;
	cout<<"   code section by lzma through dll"<<endl;
	cout<<"[2]new it can only support a little various of exe file,"<<endl;
	cout<<"   so just be regardless of the compatibility"<<endl;
	cout<<"[3]now Anti-virus software may regard the packed file as an viru"<<endl;
	cout<<"[4]other functions will be coming soon..."<<endl;
	cout<<"----useage:cmdline or drag the file on simpledpack.exe"<<endl;
	cout<<"simpledpack inpath [outpath]"<<endl;
	cout<<"----coded by devseed"<<endl;
	cout<<"-------------------------------------------------------"<<endl;
	if(argc<=1)
	{
		cout<<"input the exe path and try again!"<<endl;
		return 1;
	}
	else
	{
		DWORD res;
		char outpath[MAX_PATH];
		ifstream fin(argv[1]);
		if(fin.fail())
		{
			cout<<"#error:invalid path!"<<endl;
			return 1;
		}
		CSimpleDpack32 dpack(argv[1]);
		res=dpack.packPe();
		if(res==0)
		{
			cout<<"#error:pe pack error!"<<endl;
			return 2;
		}
		if(argc >= 3)
		{
			strcpy(outpath,argv[2]);
		}
		else
		{
			strcpy(outpath,argv[1]);
			int pos=strlen(outpath)-4;
			if(strcmp(outpath+pos,".exe"))
			{
				cout<<"#error:pe save error!"<<endl;
				return 3;
			}
			strcpy(outpath+pos,"_dpack.exe");
		}
		res=dpack.savePe(outpath);
		if(res==0)
		{
			cout<<"#error:pe save error!"<<endl;
			return 3;
		}
		cout<<"the file packed successfully("<<res<<" bytes)"<<endl;
	}
	return 0;
}
#endif