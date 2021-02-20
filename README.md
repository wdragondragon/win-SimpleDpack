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


* some of the windows EXE packing, with pe32 and ~~pe64~~ 
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

## coming soon(maybe...):

* pack multi sections (will done)
* win64 pe (will done)
* ciphering and spagetti codes to make it hard to reverse
* stolen oep codes
* ...