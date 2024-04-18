# 😡 angr
> angr Symbolic Execution 기본 문서 살펴보기

# Category
- [😡 angr](#-angr)
- [Category](#category)
  - [Logging](#logging)
  - [Project](#project)
    - [Loading Options](#loading-options)
      - [Basic Options](#basic-options)
      - [Pre-binary Options](#pre-binary-options)
    - [Symbolic Function Summaries](#symbolic-function-summaries)
      - [Hooking](#hooking)
  - [Loader](#loader)
    - [Loaded Objects](#loaded-objects)
    - [Symbols and Relocations](#symbols-and-relocations)
  - [Factory](#factory)
    - [Blocks](#blocks)
    - [States](#states)
      - [State Presets](#state-presets)
      - [Solver Engine](#solver-engine)
        - [Symbolic Constraints](#symbolic-constraints)
        - [Constraint Solving](#constraint-solving)
        - [Floating Point Numbers](#floating-point-numbers)
    - [Simulation Managers](#simulation-managers)
  - [Analyses](#analyses)

## Logging
```py
import logging
logging.getLogger('angr').setLevel('DEBUG') # DEBUG logging from angr entire module
logging.getLogger('angr.analyses').setLevel('INFO') # INFO logging from angr.analyses module
```

## Project
```py
proj = angr.Project('/bin/true')
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```
추가적으로 `arch.bits`, `arch.bytes`, `arch.name`, `arch.memory_endness` 등 Arch 클래스로부터 값을 가져올 수 있다.

### Loading Options
프로젝트를 만들 때, `cle.loader`가 암묵적으로 생성되는데, `Project` 생성자에 옵션을 넣어 전달하면 CLE로 옵션을 전달할 수 있다.
#### Basic Options
- `auto_load_libs = True` 
  
    CLE가 자동으로 shared library dependencies를 resolve한다.
- `except_missing_libs = True`
  
    resolve될 수 없는 shared library dependencies가 존재할 경우 예외를 던진다.
- `force_load_libs = [""]`

    treat unresolved library dependency right out of the gate 
- `skip_libs = [""]`

    dependency가 resolve되지 않도록 막는다.
  
- `ld_path = [""]`

    추가적인 shared library의 검색 경로를 지정한다.
#### Pre-binary Options
특정 바이너리에만 적용시킬 수 있는 옵션들은 다음과 같다.
- `main_opts = {}`

    옵션 이름, 값을 mapping하여 메인 바이너리에 적용시킬 수 있는 옵션이다.
    - `backend`
    - `base_addr`
    - `entry_point`
    - `arch`
    
- `lib_opts = {}`

    라이브러리 이름과 옵션 이름, 값을 mapping하여 적용시킬 수 있는 옵션이다.
```py
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'},
<Project examples/fauxware/fauxware
```
### Symbolic Function Summaries
`Project`는 기본적으로 external call을 library function으로 대체시킨다. 이는 `SimProcedures`라고 하는 symbolic summaries를 이용한 것인데, library function의 state에 미치는 영향을 Python function으로 immitate 해놓은 것이다. `angr.SIM_PROCEDUERS` dictionary를 통해 접근할 수 있다.

이를 통해 로드되는 library function을 더욱 추적 가능하고, 정확하게 만들 수 있다.
- `auto_load_libs = True`

    실제 library function을 부른다. 만약 library function이 분석하기 매우 복잡할 경우 path explosion이 발생할 확률이 높다.
- `auto_load_libs = False`

    external call들이 unresolved 된다. `Project`가 이를 `Simprocedures`의 `ReturnUnconstrained`라는 generic stub으로 resolve 한다. 이를 통해 각 external call들은 unique unconstrained symbolic value를 가지게 된다.
- `use_sim_proceduers = False`

    extern object로부터만 symbol이 제공되며, 이는 `Simprocedures`로 대체된다.
- `exclude_sim_proceduers_list = []` or `exclude_sim_proceduers_func = func`

    위 옵션을 통해 `Simprocedures`로 대체되지 못하게 막을 수 있다. 
#### Hooking
상기의 과정은 external call을 hooking을 통해 symbolic summaries로 대체하여 진행된다. 이는 다음과 같이 사용자도 진행할 수 있다.
```py
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func()) # hook with an instance of the class
>>> proj.is_hooked(0x10000) # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)
>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1
>>> proj.is_hooked(0x20000)
True
```
또한 `proj.hook_symbol(name, hook)`을 통해 symbol이 살아있는 모든 해당 주소에 hooking을 걸 수 있다.

## Loader
```py
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>
>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}
>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000
>>> proj.loader.main_object # we've loaded several binaries into this project. Here's the mai
<ELF Object true, maps [0x400000:0x60721f]>
>>> proj.loader.main_object.execstack # sample query: does this binary have an executable sta
False
>>> proj.loader.main_object.pic # sample query: is this binary position-independent?
True
```
CLE(CLE Load Everyting)라고 불리는 모듈을 통해 angr의 가상 영역으로 바이너리를 로드한다..

### Loaded Objects
```py
# All loaded objects
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
<ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
<ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]
# This is the "main" object, the one that you directly specified when loading the project
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>
# This is a dictionary mapping from shared object name to object
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }
# Here's all the objects that were loaded from ELF files
# If this were a windows program we'd use all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
<ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]
# Here's the "externs object", which we use to provide addresses for unresolved imports and an
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>
# This object is used to provide addresses for emulated syscalls
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>
# Finally, you can to get a reference to an object given an address in it
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```
```py
obj = proj.loader.main_object
# The entry point of the object
>>> obj.entry
0x400580
>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)
# Retrieve this ELF's segments and sections
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
<ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
<.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
<.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
...etc
# You can get an individual segment or section by an address it contains:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>
# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'
# Show the prelinked base of the object and the location it was actually mapped into memory by
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```
위와 같은 object들에서 직접적으로 metadata를 뽑아낼 수 있다.

### Symbols and Relocations
```py
>>> strcmp = proj.loader.find_symbol('strcmp')
>>> strcmp
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```
```py
>>> strcmp.name
'strcmp'
>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>
>>> strcmp.rebased_addr # 전역 주소
0x1089cd0
>>> strcmp.linked_addr # prelinked base의 offset
0x89cd0
>>> strcmp.relative_addr # object base의 offset
0x89cd0
```
```py
>>> strcmp.is_export
True
>>> strcmp.is_import
False
# On Loader, the method is find_symbol because it performs a search operation to find the symb
# On an individual object, the method is get_symbol because there can only be one symbol with
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```
`main_object`에서 직접적으로 symbol을 얻게 되면 CLE는 이를 import 되었다고 말한다. import symbol은 그 자체만으로는 의미가 없고 external symbol을 참조하고 있다.(이를 symbol을 resolve한다라고 말한다.)

imports와 exports의 연결은 relocations라고 불리는 메모리에 등록되어야 한다.
`.imports`를 통해 symbol의 name과 relocation을 맵핑하고, `.relocs`를 통해 exports symbol과 연결된다.

import symbol이 해당항는 shared library가 존재하지 않아 resolve되지 않을 경우 CLE는 자동으로 `loader.extern_obj`에 export symbol을 claim한다.

## Factory
### Blocks
```py
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry poi
<Block for 0x401670, 42 bytes>
>>> block.pp() # pretty-print a disassembly to stdout
0x401670: xor ebp, ebp
0x401672: mov r9, rdx
0x401675: pop rsi
0x401676: mov rdx, rsp
0x401679: and rsp, 0xfffffffffffffff0
0x40167d: push rax
0x40167e: push rsp
0x40167f: lea r8, [rip + 0x2e2a]
0x401686: lea rcx, [rip + 0x2db3]
0x40168d: lea rdi, [rip - 0xd4]
0x401694: call qword ptr [rip + 0x205866]
>>> block.instructions # how many instructions are there?
0xb
>>> block.instruction_addrs # what are the addresses of the instructions?
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```
```py
>>> block.capstone # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex # VEX IRSB (that's a Python internal address, not a p
<pyvex.block.IRSB at 0x7706330>
```

### States
```py
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
>>> state.regs.rip # get the current instruction pointer
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>
```
`SimState` 오브젝트를 통해 Simulated Program State를 변경할 수 있다.

```py
>>> bv = state.solver.BVV(0x1234, 32) # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234> # BVV stands for bitvector value
>>> state.solver.eval(bv) # convert to Python int
0x1234
```
```py
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>
>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
>>> state.mem[0x1000].long.concrete
4
```

#### State Presets
- `.blank_state()`

    비어있는 상태, 대부분의 데이터가 uninitialized 상태이며 이에 접근할 시 unconstrained symbolic value가 return 된다.
- `.entry_state()`
- `.full_init_state()`

    메인 바이너리의 entry point를 실행하기 전 필요한 initializers(shared library initializer, preinitializer, etc)들을 모두 실행한 후 entry point를 실행한다.
- `.call_state()`

    주어진 함수로부터 실행이 가능한 상태이다.

    `.call_state(addr, arg1, arg2, ...)` 형태로 실행하며, 메모리를 할당하여 포인터를 주고 싶은 경우 `PointerWrapper`를 이용하여 `angr.PointerWrapper("point to me!")`과 같이 사용하면 된다. calling convention을 지정할 경우, `SimCC instance`를 인자로 넘기면 되는데, 이는 `cc` 옵션을 통해 가능하다.

아래 인자들을 통해 state constructor를 customize할 수 있다.
- `addr=?`

    특정 주소로부터 시작할 수 있다.
- `args=[], env={}, argc=?`

    인자 및 환경 변수를 설정할 수 있다. `argc`를 설정할 경우, 설정한 `args`의 개수보다 높아질 수 없도록 constraint를 추가하여야 한다.

#### Solver Engine
symbolic value와 함께 artihmetic operation을 진행할 때 이는 ASTs(Abstract Syntax Tree)라고 하는 연산 Tree를 만든다.
```py
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> weird_nine.sign_extend(64 - 27)
<BV64 0x9>
```
```py
>>> x = state.solver.BVS('x', 64)
>>> y = state.solver.BVS('y', 64)
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
```

##### Symbolic Constraints
```py
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```
BitVector에서 `-5`는 기본적으로 unsinged로 처리되기 때문에 `<BV64 0xfffffffffffffffb>`로 표현된다. 이를 signed로 처리하기 위해서 `one_hundred.SGT(-5)`를 사용하면 된다.(Signed Greater Than)
```py
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```
Python의 if 문이나 while 문에서 >, <와 같은 비교 연산자는 허용되지 않으며 오류를 일으킨다. 때문에, `is_true` 혹은 `is_false`를 이용해야 한다.

##### Constraint Solving
```py
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
>>> state.satisfiable()
True
```
```py
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

##### Floating Point Numbers
z3은 `IEEE754` 의 부동소수점 연산을 지원한다. angr는 내부적으로 z3을 이용하고 있기 때문에 똑같이 이를 지원한다.
```py
# fresh state
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>
>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>
>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>
```
`solver.fp.RM_*`를 통해 Rounding Mode를 설정할 수 있다.
```py
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```
Floating Point에서 `-1`은 unsigned로 처리되지 않는다.
```py
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>
>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```
bitVector <-> Floating Point가 가능하다.

```py
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```
`raw_to_*`는 비트를 보존하지만 `val_to_*`는 값을 보존한다.
- `solver.eval(expression)`
- `solver.eval_one(expression)`
- `solver.eval_upto(expression, n)`
- `solver.eval_atleast(expression, n)`
- `solver.eval_exact(expression, n)`
- `solver.min(expression)`
- `solver.max(expression)`

위 모든 함수에 추가할 수 있는 인자들은 다음과 같다.
- `extra_constraints`

    tuple list 형태로 `SimState`에 추가되지 않는 추가적인 constraints를 제공할 수 있다.

- `cast_to`

    `int, bytes` 형태로 값을 cast할 수 있다.
    ```py
    state.solver.eval(state.solver.BVV(0x41424344, 32),cast_to=bytes) will return b'ABCD'
    ```

### Simulation Managers
```py
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```
`SimulationManager`를 통해 `SimState`와 함께 Simulation을 진행할 수 있다.

```py
simgr.step()
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip # still the same!
<BV64 0x401670>
```
`SimulationManager`를 통해 Simulation을 진행하여도 원본 `SimState`는 immutable 오브젝트기 때문에 변하지 않는다.

`state.step`은 `SimSuccessors` 오브젝트를 return 하는데, 이는 branch를 저장하는 오브젝트이다. 예를 들어, `if x > 4`라는 코드에 도달했을 경우, angr는 이를 `<BOOL x_32_1 > 4>`라는 symbolic value로 변경하고, 조건을 통과한 경우와 조건을 통과하지 않은 경우(`!(if x > 4)`)를 `SimSuccessors` 오브젝트에 저장한다.
```py
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile) # ignore that argument for now - we
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]
>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```
```py
>>> input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)
>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'
>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```


## Analyses
```py
# Originally, when we loaded this binary it also loaded all its dependencies into the same vir
# This is undesirable for most analysis.
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>
# cfg.graph is a networkx DiGraph full of CFGNode instances
# You should go look up the networkx APIs to learn how to use this!
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951
# To get the CFGNode for a given address, use cfg.get_any_node
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```
