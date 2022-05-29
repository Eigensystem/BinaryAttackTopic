from ae64 import AE64
from pwn import *
context.arch='amd64'

# get bytes format shellcode
shellcode = asm(shellcraft.sh())

# get alphanumeric shellcode
enc_shellcode = AE64().encode(shellcode, 'rdx', 0, 'fast')
print(enc_shellcode.decode('latin-1'))