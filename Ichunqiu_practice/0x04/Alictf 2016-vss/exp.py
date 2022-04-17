from pwn import *
context(log_level = 'Debug', arch = 'amd64', os = 'linux')
io = process("./vss")
#io = remote("114.55.66.54", 10001)
gdb.attach(io)

io.recv()
io.sendline("hah")
io.recvall()