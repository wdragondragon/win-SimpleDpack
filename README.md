# SimpleDpack
A  very simple windows EXE packing tool, 

for learning or investigating PE structure.

Designed by [devseed](https://github.com/YuriSizuku/SimpleDpack).

### usage:

```SH
::cmdline or drag the file on simpledpack.exe
simpledpack inpath [outpath]
simpledpack64 inpath [outpath]
```


## features：


* some of the windows EXE packing, with pe32 and pe64 (I have test the hello world program packing) 
* using LZMA for pack multi sections (except rsrc section)
* the shell code are compiled in DLL by C,  then appended in exe after adjusting each of the address recorded in .reloc.
* it can be easily to expand

## structures

```
[dpack packing project]
debugtry.c       // functions to debug
WinConsole.cpp   // cmd shellPeInfo.cpp			  
CPInfo.cpp       // base class CPEinfo to inspect pe	files, such as addr converter
CPEedit.cpp      // a class to edit the pe structure
SimpleDpack.cpp  // base class CSimpleDpack to pack pe

[dpack shell dll]
simpledpackshell.cpp    // shell code to start packed pe
dllmain                            

[packing program code]
dpackProc.c	    // pack functions
dunpackProc.c   // unpack functions
dpackType.c     // structures decleare
```

## versions log:

* v0.1(initial release)
  * lzma compress only code section in win32 exe
  * c++ class to resolve pe(win32 exe),util fuctions
  * relocate the shell codes dll(c) and add in win32 exe
* v0.1.1 update the tool to vs2019
* v0.2 rewrite some code and make it more clear,  merge the pe32 and pe64 structure
* v0.3 refracts the class and code, removing useless code, to make it more easy to understand 
* v0.3.1 make pack program workflow clean
* v0.3.2  appendSection, savePe rewrite,  merge the shellcode and packed data into one section
* v0.4 multi section (except rsrc) pack finished!
* v0.5 x64 supprot!
* v0.5.1 fixed IAT FT pointer to OFT problem
* v0.5.2 fix reloc problem, compatible with windows XP, change code to utf8bom
* v0.5.3  fix the problem by `GetProcAddress ` when using ordinal

## coming soon(maybe...):

* ~~pack multi sections (done)~~
* ~~win64 pe (done)~~
* ~~improve the compatibility ? (I don't know why some of the x64 exe can not start after changing OEP...)~~fixed in v0.5.3
* ...