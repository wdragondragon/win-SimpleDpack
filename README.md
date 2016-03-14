# SimpleDpack
<p>windows pe packing 
<p>This is an aplication for packing windows pe image.
<p>Designed by devseed(also 小木曾雪菜,YuriSizuku)


<p>useage:cmdline or drag the file on simpledpack.exe
<p>      simpledpack inpath [outpath]

<p>attentions:
<p>[1]the initial demo version that can pack the pe32 exe file
<p>   code section by lzma through dll
<p>[2]new it can only support a little various of exe file,
<p>   so just be regardless of the compatibility
<p>[3]now Anti-virus software may regard the packed file as an viru
<p>[4]other functions will be coming soon...

<p>coming soon:
<p>+more compatible version
<p>+pack multi sections
<p>+win64 pe
<p>+dll
<p>+ciphering and spagetti codes to make it hard to reverse
<p>+stolen oep codes
<p>+...

<p>versions:
<p>v0.1(initial release)
<p>#lzma compress only code section in win32 exe
<p>#c++ class to resolve pe(win32 exe),util fuctions
<p>#relocate the shell codes dll(c) and add in win32 exe
