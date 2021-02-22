#include "SimpleDpack.hpp"
#include "debugtry.h"
#include <iostream>
#include <fstream>
using namespace std;
#ifndef _DEBUGTRY
/*
	SimpleDpack console ver0.3.2 Console
	simpledpack inpath [outpath]
*/
int main(int argc,char *argv[])
{
	cout<<"-----------------SimpleDpack ver0.3.2--------------------"<<endl;
	cout << "A very simple windows EXE packing tool, " << endl;
	cout << "for learning or investigating PE structure. " << endl;
	cout << "designed by devseed" << endl;
	cout<<"--useage:cmdline or drag the file on simpledpack.exe"<<endl;
	cout<<"simpledpack inpath [outpath]"<<endl;
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
		cout<<"the file packed successfully(0X"<<hex<<res<<" bytes)"<<endl;
	}
	return 0;
}
#endif