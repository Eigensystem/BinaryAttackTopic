from os import environ
from pwn import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
io = process("./silverwolf")
# io = remote("124.70.130.92", 60001)
# gdb.attach(io)

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(str(delim), data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(str(delim), data)
r       = lambda num=4096           :io.recv(num)
ru      = lambda delims             :io.recvuntil(delims)
rl      = lambda                    :io.recvline()
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

def add(size):
    ru("Your choice: ")
    sl("1")
    ru("Index: ")
    sl("0")
    ru("Size: ")
    sl(str(size))

def edit(content):
    ru("Your choice: ")
    sl("2")
    ru("Index: ")
    sl("0")
    ru("Content: ")
    sl(content)

def show():
    ru("Your choice: ")
    sl("3")
    ru("Index: ")
    sl("0")
    ru("Content: ")

def delete():
    ru("Your choice: ")
    sl("4")
    ru("Index: ")
    sl("0")

