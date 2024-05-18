# 👻 pwntools
> pwntools 쓸만한 기능들 정리

# Catalog
- [👻 pwntools](#-pwntools)
- [Catalog](#catalog)
  - [File i/o](#file-io)
  - [Hashing and encoding](#hashing-and-encoding)
    - [Base64](#base64)
    - [Hashes](#hashes)
    - [URL Encoding](#url-encoding)
    - [Hex Encoding](#hex-encoding)
    - [Bit Manipulation](#bit-manipulation)
    - [Hex Dumping](#hex-dumping)
  - [Using symbols](#using-symbols)
  - [Changing the base address](#changing-the-base-address)
  - [Reading elf files](#reading-elf-files)
  - [Patching elf files](#patching-elf-files)
  - [Searching elf files](#searching-elf-files)
  - [Buliding elf files](#buliding-elf-files)
  - [Canned assembly](#canned-assembly)
  - [Syscall assembly](#syscall-assembly)
  - [Attaching to a running process](#attaching-to-a-running-process)
  - [Debugging foreign architecture](#debugging-foreign-architecture)
  - [Specifying a terminal window](#specifying-a-terminal-window)
  - [Calling function by name](#calling-function-by-name)
  - [Getting a shell](#getting-a-shell)
  - [Return to dl\_resolve](#return-to-dl_resolve)
  - [Return oriented programming](#return-oriented-programming)
  - [Sigreturn oriented programming](#sigreturn-oriented-programming)
    - [x64](#x64)
    - [x86](#x86)
  - [Return to csu](#return-to-csu)
  - [Format string bug](#format-string-bug)


## File i/o
```py
from pwn import *

write('filename', 'data')
read('filename')
# 'data'
read('filename', 1)
# 'd'
```

## Hashing and encoding
### Base64
```py
'hello' == b64d(b64e('hello'))
```
### Hashes
```py
md5sumhex('hello') == '5d41402abc4b2a76b9719d911017c592'
write('file', 'hello')
md5filehex('file') == '5d41402abc4b2a76b9719d911017c592'
sha1sumhex('hello') == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
```
### URL Encoding
```py
urlencode("Hello, World!") == '%48%65%6c%6c%6f%2c%20%57%6f%72%6c%64%21'
```
### Hex Encoding
```py
enhex('hello')
# '68656c6c6f'
unhex('776f726c64')
# 'world'
```
### Bit Manipulation
```py
bits(0b1000001) == bits('A')
# [0, 0, 0, 1, 0, 1, 0, 1]
unbits([0,1,0,1,0,1,0,1])
# 'U'
```
### Hex Dumping
```py
print hexdump(read('/dev/urandom', 32))
# 00000000  65 4c b6 62  da 4f 1d 1b  d8 44 a6 59  a3 e8 69 2c  │eL·b│·O··│·D·Y│··i,│
# 00000010  09 d8 1c f2  9b 4a 9e 94  14 2b 55 7c  4e a8 52 a5  │····│·J··│·+U|│N·R·│
# 00000020
```

## Using symbols
```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> license" % e.symbols['bash_license']
print "%#x -> execve" % e.symbols['execve']
print "%#x -> got.execve" % e.got['execve']
print "%#x -> plt.execve" % e.plt['execve']
print "%#x -> list_all_jobs" % e.functions['list_all_jobs'].address
```

## Changing the base address
```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']

print "---"
e.address = 0x12340000

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']
```

## Reading elf files
```py
from pwn import *

e = ELF('/bin/bash')

print repr(e.read(e.address, 4))

p_license = e.symbols['bash_license']
license   = e.unpack(p_license)
print "%#x -> %#x" % (p_license, license)

print e.read(license, 14)
print e.disasm(e.symbols['main'], 12)
```

## Patching elf files
```py
from pwn import *

e = ELF('/bin/bash')

# Cause a debug break on the 'exit' command
e.asm(e.symbols['exit_builtin'], 'int3')

# Disable chdir and just print it out instead
e.pack(e.got['chdir'], e.plt['puts'])

# Change the license
p_license = e.symbols['bash_license']
license = e.unpack(p_license)
e.write(license, 'Hello, world!\n\x00')

e.save('./bash-modified')
```

## Searching elf files
```py
from pwn import *

e = ELF('/bin/bash')

for address in e.search('/bin/sh\x00'):
    print hex(address)
```

## Buliding elf files
```py
from pwn import *

ELF.from_bytes('\xcc').save('int3-1')
ELF.from_assembly('int3').save('int3-2')
ELF.from_assembly('nop', arch='powerpc').save('powerpc-nop')
```

## Canned assembly
```py
context.arch = 'amd64'

sc = shellcraft.mov('rax', 0xdeadbeef)
sc += shellcraft.itoa('rax')
sc += shellcraft.write(1, 'rsp', 32)
```

## Syscall assembly
```py
context.arch = 'amd64'

sc = shellcraft.syscall('SYS_execve', 1, 'rsp', 2, 0)
run_assembly(sc)
```

## Attaching to a running process
```py
>>> io = process('/bin/sh')
>>> gdb.attach(io, gdbscript='continue')
```
## Debugging foreign architecture
```py
>>> context.arch = 'arm'
>>> elf = ELF.from_assembly(shellcraft.echo("Hello, world!\n") + shellcraft.exit())
>>> process(elf.path).recvall()
```
## Specifying a terminal window
```py
>>> context.terminal = ['tmux', 'splitw', '-h']

>>> context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
```

## Calling function by name
```py
context.binary = elf = ELF('/bin/sh')
rop = ROP(elf)
rop.execve(0xdeadbeef)
print(rop.dump())
# 0x0000:           0x61aa pop rdi; ret
# 0x0008:       0xdeadbeef [arg0] rdi = 3735928559
# 0x0010:           0x5824 execve
```

## Getting a shell
```py
context.binary = elf = ELF('/bin/sh')
libc = elf.libc

elf.address = 0xAA000000
libc.address = 0xBB000000

rop = ROP([elf, libc])

binsh = next(libc.search(b"/bin/sh\x00"))
rop.execve(binsh, 0, 0)
```

## Return to dl_resolve
```py
>> rop = ROP(context.binary)
>>> dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["echo pwned"])
>>> rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
>>> rop.ret2dlresolve(dlresolve)
>>> raw_rop = rop.chain()
>>> # sendline(dlresolve.payload)
```

## Return oriented programming
```py
>>> rop = ROP(binary)
>>> rop.eax = 0xdeadf00d
>>> rop.ecx = 0xc01dbeef
>>> row.raw = 0xffffffff
```

```py
>>> rop.call('read', [4,5,6])
>>> rop.write(7, 8, 9)
```

```py
rop = ROP(elf, badchars=b'\x02\x06')
```

## Sigreturn oriented programming
### x64
```py
>>> frame = SigreturnFrame()
>>> frame.rax = constants.SYS_write
>>> frame.rdi = constants.STDOUT_FILENO
>>> frame.rsi = binary.symbols['message']
>>> frame.rdx = len(message)
>>> frame.rsp = 0xdeadbeef
>>> frame.rip = binary.symbols['syscall']
>>> p = process(binary.path)
>>> p.send(bytes(frame))
>>> p.recvline()
b'Hello, World\n'
>>> p.poll(block=True)
0
```

### x86
```py
>>> frame = SigreturnFrame(kernel='amd64')
>>> frame.eax = constants.SYS_write
>>> frame.ebx = constants.STDOUT_FILENO
>>> frame.ecx = binary.symbols['message']
>>> frame.edx = len(message)
>>> frame.esp = 0xdeadbeef
>>> frame.eip = binary.symbols['syscall']

>>> p = process(binary.path)
>>> p.send(bytes(frame))
```

## Return to csu
```py
>>> r = ROP(context.binary)
>>> r.ret2csu(1, 2, 3, 4, 5, 6, 7, 8, 9)
>>> r.call(0xdeadbeef)
```

## Format string bug
```py
>>> program = pwnlib.data.elf.fmtstr.get('i386')
>>> def exec_fmt(payload):
...   p = process(program)
...   p.sendline(payload)
...   return p.recvall()
...
>>> autofmt = FmtStr(exec_fmt)
>>> offset = autofmt.offset
>>> p = process(program, stderr=PIPE)
>>> addr = unpack(p.recv(4))
>>> payload = fmtstr_payload(offset, {addr: 0x1337babe})
>>> p.sendline(payload)
```

```py
writes = {0x08041337: 0xbfffffff,
 0x08041337+4: 0x1337babe,
 0x08041337+8: 0xdeadbeef}

# numbwritten (int) – number of byte already written by the print func!on
payload = fmtstr_payload(5, writes, numbwritten=8)
```

```py
>>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
b'%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
>>> fmtstr_payload(1, {0x0: 0x00000001}, write_size='byte')
b'%1c%3$na\x00\x00\x00\x00'
>>> fmtstr_payload(1, {0x0: b"\xff\xff\x04\x11\x00\x00\x00\x00"},
write_size='short')
b'%327679c%7$lln%18c%8$hhn\x00\x00\x00\x00\x03\x00\x00\x00'
```

