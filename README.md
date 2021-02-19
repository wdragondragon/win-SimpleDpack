# SimpleDpack
<p>windows pe packing 
<p>This is an aplication for packing windows pe image.
<p>Designed by devseed
### usage:
<p>cmdline or drag the file on simpledpack.exe
<p>simpledpack inpath [outpath]
## features：

* windows exe pe32 and ~~pe64~~ pack
* pack multi sections (except rsrc section)

### attentions:

* the initial demo version that can pack the pe32 exe file code section by lzma through dll
* new it can only support a little various of exe file,so just be regardless of the compatibility
* now Anti-virus software may regard the packed file as an viru
* other functions will be coming soon...

### coming soon:
* pack multi sections (will done)
* win64 pe (will done)
* ciphering and spagetti codes to make it hard to reverse
* stolen oep codes
* ...

### versions:
* v0.1(initial release)
  * lzma compress only code section in win32 exe
  * c++ class to resolve pe(win32 exe),util fuctions
  * relocate the shell codes dll(c) and add in win32 exe
* v0.1.1 update the tool to vs2019
* v0.2 rewrite some code and make it more clear
