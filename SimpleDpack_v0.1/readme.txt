This is an aplication for packing windows pe image.


Designed by devseed(also Ð¡Ä¾ÔøÑ©²Ë,YuriSizuku)


useage:cmdline or drag the file on simpledpack.exe
      simpledpack inpath [outpath]

attentions:
[1]the initial demo version that can pack the pe32 exe file
   code section by lzma through dll
[2]new it can only support a little various of exe file,
   so just be regardless of the compatibility
[3]now Anti-virus software may regard the packed file as an viru
[4]other functions will be coming soon...

coming soon:
+more compatible version
+pack multi sections
+win64 pe
+dll
+ciphering and spagetti codes to make it hard to reverse
+stolen oep codes
+...

versions:
v0.1(initial release)
#lzma compress only code section in win32 exe
#c++ class to resolve pe(win32 exe),util fuctions
#relocate the shell codes dll(c) and add in win32 exe