#include "SimpleDpack.hpp"
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
	cout<<"-----------------SimpleDpack ver0.2--------------------"<<endl;
	cout<<"[1]pack the pe32/pe64 exe file"<<endl;
	cout<<"   code section by lzma through dll"<<endl;
	cout<<"[2]new it can pack multi segments,"<<endl;
	cout<<"   x64 version will come soon" <<endl;
	cout<<"[3]now Anti-virus software may regard the packed file as an viru"<<endl;
	cout<<"[4]other functions will be coming soon..."<<endl;
	cout<<"----useage:cmdline or drag the file on simpledpack.exe"<<endl;
	cout<<"simpledpack inpath [outpath]"<<endl;
	cout<<"----designed by devseed"<<endl;
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
		CSimpleDpack dpack(argv[1]);
#ifdef _WIN64
		res = dpack.packPe("simpledpackshell64.dll");
#else
		res = dpack.packPe("simpledpackshell.dll");
#endif
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