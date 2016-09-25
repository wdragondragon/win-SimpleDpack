# SimpleDpack
<p>windows pe packing 
<p>This is an aplication for packing windows pe image.
<p>Designed by devseed(also 小木曾雪菜,YuriSizuku)

###usage:
<p>cmdline or drag the file on simpledpack.exe
<p>simpledpack inpath [outpath]

###attentions:
* the initial demo version that can pack the pe32 exe file code section by lzma through dll
* new it can only support a little various of exe file,so just be regardless of the compatibility
* now Anti-virus software may regard the packed file as an viru
* other functions will be coming soon...

###coming soon:
* more compatible version
* pack multi sections
* win64 pe
* dll
* ciphering and spagetti codes to make it hard to reverse
* stolen oep codes
* ...

###versions:
* v0.1(initial release)
  * lzma compress only code section in win32 exe
  * c++ class to resolve pe(win32 exe),util fuctions
  * relocate the shell codes dll(c) and add in win32 exe
