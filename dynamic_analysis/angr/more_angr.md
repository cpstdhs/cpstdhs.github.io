# 😡😡 more angr
> angr 기본 문서의 심화적인 내용 추가로 정리

# Category
- [😡😡 more angr](#-more-angr)
- [Category](#category)
  - [Low level interface for memory](#low-level-interface-for-memory)
  - [State Options](#state-options)
  - [State Plugins](#state-plugins)
    - [The globals plugin](#the-globals-plugin)
    - [The history plugin](#the-history-plugin)
    - [The callstack plugin](#the-callstack-plugin)
  - [Copying and Merging](#copying-and-merging)
  - [Simulation Managers](#simulation-managers)
    - [stash management](#stash-management)
  - [Stash types](#stash-types)
  - [Exploration Techniques](#exploration-techniques)
  - [Execution Engines](#execution-engines)
  - [SimSuccessors](#simsuccessors)
  - [Breakpoints](#breakpoints)
  - [Built-in Analyses](#built-in-analyses)
    - [General ideas](#general-ideas)
    - [Using the CFG](#using-the-cfg)
    - [Shared Libraries](#shared-libraries)
    - [Fucntion Manager](#fucntion-manager)
    - [CFGFast details](#cfgfast-details)
      - [Finding function starts](#finding-function-starts)
      - [FakeRets and function returns](#fakerets-and-function-returns)
      - [Options](#options)
    - [CFGEmulated details](#cfgemulated-details)
      - [Options](#options-1)
    - [Backward Slicing](#backward-slicing)
      - [Using The `BackwardSlice` Object](#using-the-backwardslice-object)
  - [Gotchas](#gotchas)
    - [SimProcedure inaccuracy](#simprocedure-inaccuracy)
    - [Unsupported syscalls](#unsupported-syscalls)
    - [Symbolic memory model](#symbolic-memory-model)
    - [Symbolic lengths](#symbolic-lengths)
    - [Division by Zero](#division-by-zero)
  - [General speed tips](#general-speed-tips)
  - [If you're performing lots of concrete or partially-concrete execution](#if-youre-performing-lots-of-concrete-or-partially-concrete-execution)
  - [The Emulated Filesystem](#the-emulated-filesystem)
    - [Example 1 Create a file with concrete content](#example-1-create-a-file-with-concrete-content)
    - [Example 2 Create a file with symbolic content and a defined size](#example-2-create-a-file-with-symbolic-content-and-a-defined-size)
    - [Example 3 Create a file with constrained symbolic content](#example-3-create-a-file-with-constrained-symbolic-content)
    - [Example 4 Create a file with some mixed concrete and symbolic content, but no EOF](#example-4-create-a-file-with-some-mixed-concrete-and-symbolic-content-but-no-eof)
    - [Example 5 Create a file with a symbolic size ( has_end is implicitly true here](#example-5-create-a-file-with-a-symbolic-size--has_end-is-implicitly-true-here)
    - [Example 6: Working with streams ( `SimPackets` )](#example-6-working-with-streams--simpackets-)
  - [Stdio streams](#stdio-streams)
  - [Intermediate Representation](#intermediate-representation)
  - [Claripy ASTs](#claripy-asts)
  - [Solvers](#solvers)

## Low level interface for memory
```py
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```
`state.mem`으로도 raw data를 넣을 수 있긴 하지만 이는 굉장히 귀찮아진다. `state.memory`를 사용하면 memory와 raw data로 직접적으로 소통할 수 있다.

```py
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67452301>
```
`state.memory`의 주 목적은 문법에 얽매이지 않고 raw data를 다룰 수 있는 것에 있기 때문에 기본적으로 big-endian으로 저장이 된다. 이는 `archinfo.Endness` enum을 통해 변경할 수 있다.

## State Options
```py
# Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible
# This change to the settings will be propagated to all successor states created from this state
>>> s.options.add(angr.options.LAZY_SOLVES)
# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```
`angr.options` enum을 통해 `state`에 옵션을 지정할 수 있다.

## State Plugins
`memory , registers , mem , regs , solver` 등 여태까지 살펴본 수많은 property들이 모두 state plugin이다. 이러한 plugin들을 통해 code complexity를 줄일 수 있다.

### The globals plugin
`state.globals`은 python dict를 사용하여 state를 다룰 수 있게 해주는 plugin이다.

### The history plugin
`state.history`는 실행 중의 historical data를 linked-list 형태로 가지고 있는 plugin이다.

`state.history.parent.parent ~`를 통해 linked-list를 이용할 수 있다.

- `history.recent_NAME`

    historical data list이다.

- `history.NAME`

    historical data iterator이다.

- `history.NAME.hardcopy`

    모든 parent들의 historical data list를 얻어올 수 있다.

위의 `NAME`에 해당하는 history value들은 간단하게 다음과 같다.
- `history.descriptions`

    state 실행 관련된 설명이다.
- `history.bbl_addrs`

    state에 의해 실행된 basic block의 주소이다. (hooking이 된 경우 실제 바이너리 주소와 다를 수 있다.)
- `history.jumpkinds`

    control flow transition list이다. (VEX enum string)
- `history.jump_guards`

    state가 마주친 conditions guarding list이다. (조건들인듯)s
- `history.events`

    message box를 띄웠거나, terminate 됐거나, symbolic jump condition이 있는 등의 interesting event를 기록한다.

- `history.actions`

    `angr.options.refs`를 state에 추가하면 memory, register, temporary value access 등을 기록한다. 보통 비어있다.

### The callstack plugin
`state.history`와 비슷한데, `state.callstack`이라는 iterator 하나만 주어진다.

- `callstack.func_addr`

    최근 실행된 함수의 주소이다.
- `callstack.call_site_addr`

    현재 함수를 호출한 basic block의 주소이다.
- `callstack.stack_ptr`

    현재 함수의 시작 stack pointer이다.

- `callstack.ret_addr`

    현재 함수가 return할 주소이다.

## Copying and Merging
```py
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()
>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242
```
```py
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)
# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t
```

## Simulation Managers
state들은 stashes로 그룹화된다. step forward, merge, filter, move가 가능하다.

```py
# Step until the first symbolic branch
>>> while len(simgr.active) == 1:
...     simgr.step()
>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]
# Step until everything terminates
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```
symbolic branch condition을 만날 경우, 두 개의 state로 나뉘어 stash로 들어가며 그저 끝까지 실행시키고 싶을 때는 `.run()`을 사용하면 된다.

### stash management
```py
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welco
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```
```py
>>> for s in simgr.deadended + simgr.authenticated:
... print(hex(s.addr))
0x1000030
0x1000078
0x1000078
>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```
`one_`을 통해 stash의 첫 번째 state를 가져올 수 있고 `mp_`를 통해 stash의 mulpyplexed 버전을 가져올 수 있다.

## Stash types
- `active`
- `deadended`
- `pruned`

    state option에 `LAZY_SOLVES`가 설정돼 있을 경우 꼭 필요할 때만 satisfiablilty를 확인하는데, `state.history`를 참조하여 unsat이 된 이유를 찾는다. 이러한 state들이 `pruned`에 들어가게 된다.
- `unconstrained`

    사용자의 데이터에 의하여 혹은 symbolic data에 의하여 instrunction pointer가 변경되는 것 같이 제약 없는 상태의 state들이 `unconstrained`에 들어가게 된다.
- `unsat`

    모순된 제약 조건ㅇㄹ 갖고 있는 것 같이 충족될 수 없는 상태의 state들이 `unsat`에 들어가게 된다.

또한 `erroed` 라는 stash가 아닌 state들의 list가 존재하는데, `record.state`에 에러가 발생한 시작 부분의 execution tick가 저장되며, `record.error`에 에러가 저장된다. 이는 `record.debug()`를 통해 디버깅까지 할 수 있다.

## Exploration Techniques
simulation manager는 탐색 기술로 기본적으로 BFS(Breadth-First-Search)를 사용하고 있는데, 이 외에도 여러 가지 custom 탐색 기법 혹은 내장 탐색 기법을 사용할 수 있다: 

`simgr.use_technique(tech)`, `angr.exploration_techniques`

- `DFS(Depth-First-Search)`

    한 번에 하나의 state만 `active` stash, 나머지는 `deferred` stash 에 넣고 작업한다.
- `Explorer`

    `simgr.explore`와 같이 search, avoid address 등을 지원한다.
- `LengthLimiter`

    state의 최대 길이를 설정한다.
- `LoopSeer`

    loop가 너무 많이 돈다 싶으면 이를 `spinning` stash로 이동시키고, 다른 state의 작업이 모두 종료된 후 이를 수행한다.
- `ManualMergePoint`

    프로그램의 merge point address를 설정하고, 이 곳에 도달하는 state끼리 merge를 진행한다.

- `MemoryWatcher`

    simgr에 의한 free/available memory를 감시한다.
- `Oppologist`

    SIMD와 같은 지원하지 않는 연산을 만났을 때, 이를 unicorn engine을 이용하여 수행한다.
- `Spiller`

    active state가 너무 많을 때, 메모리를 절약하기 위하여 일부를 disk에 dump한다.
- `Threading`

    gil때문에 별 효과가 없지만 angr의 native-code dependencies(unicorn, z3, libvex)가 오래 걸릴 경우 효과가 있다.
- `Tracer`

    동적으로 추적 기록을 남겨준다.
- `Veritesting`

    자동으로 유용한 merge point를 인지한다.

## Execution Engines
`angr`는 state에 해당 코드가 미치는 영향을 emulate하기 위하여 `SimEngine` class의 subclass인 엔진들을 사용한다.
`angr`의 execution core는 이용 가능한 엔진들을 단순히 나열하여 첫 번째로 나열된 엔진으로 코드를 수행한다. 엔진들은 다음과 같다.
- `failure engine`
- `syscall engine`
- `hook engine`
- `unicorn engine`: `UNICORN` state option이 활성화 되어있고 state에 symbolic data가 없을 경우 사용된다.
- `VEX engine`: final fallback에 사용된다.

## SimSuccessors
`SimSuccessors`는 successor state를 간단하게 분류한다.
- `successors`: satisfiable successor state이다. 즉, SAT solve가 가능한 상태이다.(True 값을 얻을 수 있는 상태)
  - Guard Condition: True (can be symbolic, but constrained to True)
  - Instruction Pointer: Can be symbolic (but 256 solutions or less)
- `unsat_successors`: Unsatisfiable successors이다. 예를 들어, 진행될 수 없는 jump와 같이 이 successor의 guard condition은 오직 false만 될 수 있다.
  - Guard Condition: False(can be symbolic, but constrained to False)
  - Instruction Pointer: Can be Symbolic.
- `flat_successors`: 256(threshold)개 까지 가능한 concrete solution들을 계산하고, 각각의 solution들을 state의 복사본으로 만든다. 이를 process "flattening"이라고 한다. 예를 들어, state의 instruction pointer `successors`가 `X+5`이고, constraints가 `X > 0x800000 and X < 0x800010`일 경우 각각 다른 16개의 `flat_successors` state로 flattening된다.
  - Guard Condition: True(can be symbolic, but constrained to True)
  - Instruction Pointer: Concrete value.
- `unconstrained_succesors`
  - Guard Condtion: True(can be symbolic, but constrained to True)
  - Instruction Pointer: Symbolic (with more than 256 solutions).
- `all_successors`: `flat_successors`를 제외한 모든 `successors`

## Breakpoints
```py
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')
# get our state
>>> s = b.factory.entry_state()
# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')
# on the other hand, we can have a breakpoint trigger right *after* a memory write happens.
# we can also have a callback function run instead of opening ipdb.
>>> def debug_func(state):
... print("State %s is about to do a memory write!")
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)
# or, you can have it drop you in an embedded IPython!
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

`mem_write` 말고도 여러 event들이 존재하는데, 이는 다음과 같다.
- mem_read: 메모리 읽힘
- mem_write: 메모리 써짐
- address_concretization: symbolic memory access가 resolve됨
- reg_read: 레지스터 읽힘
- reg_write: 레지스터 써짐
- tmp_read: temp 읽힘
- tmp_write: temp 써짐
- expr: expression이 생성됨
- statement: IR statement가 translated됨
- instruction: new(native) instruction이 translated됨
- irsb: 새로운 basic block이 translated됨
- constraints: 새로운 constraints가 state에 추가됨
- exit: successor가 실행으로부터 생성됨
- fork: symbolic execution state가 여러 state로 fokr됨
- symbolic_variable: 새로운 symbolic variable이 생성됨
- call: call 만남
- return: return 만남
- simprocedure: simproecedure(or syscall)이 실행됨
- dirty: dirty IR callback이 실행됨
- syscall: syscall이 실행됨(simprocedure event와 함께 불림)
- engine_process: `SimEngine`이 코드를 실행하려 함

이러한 이벤트들에서 뽑아낼 수 있는 읽은 주소, 읽은 표현, 읽은 길이 등의 attribute들이 존재하는데, 많으니 따로 `angr` docs를 참고하도록 한다.

## Built-in Analyses
- `CFGFast`
- `CFGEmulated`
- `VFG`: 프로그램의 모든 함수에 VSA 를 수행하여 VFG를 만든다.
- `DDG`
- `BackwardSlice`

### General ideas
CFG는 개념적으로 basic block을 node로, jumps/calls/rets 등을 edge로 가지는 그래프이다. 

`angr`에서는 static CFG(CFGFast)와 dynamic CFG(CFGEmulated)가 존재한다.

```py
>>> import angr
# load your project
>>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})
# Generate a static CFG
>>> cfg = p.analyses.CFGFast()
# generate a dynamic CFG
>>> cfg = p.analyses.CFGEmulated(keep_state=True)
```

### Using the CFG
```py
>>> print("This is the graph:", cfg.graph)
>>> print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
```
```py
# this grabs *any* node at a given location:
>>> entry_node = cfg.get_any_node(p.entry)
# on the other hand, this grabs all of the nodes
>>> print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))
# we can also look up predecessors and successors
>>> print("Predecessors of the entry point:", entry_node.predecessors)
>>> print("Successors of the entry point:", entry_node.successors)
>>> print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node) ])
```

### Shared Libraries
`auto_load_libs` 옵션을 `False`로 만들지 않고 CFG를 만들 시 로드된 shared library들을 통해 분석을 진행하는데, 이는 아주 많은 시간이 소요됨을 의미한다. 때문에 CFG를 다룰 때는 위의 옵션을 넣어주는 것이 좋다.

### Fucntion Manager
주소를 함수의 속성에 관한 정보를 담고 있는 `Function` 객체로 맵핑한다.
```py
>>> entry_func = cfg.kb.functions[p.entry]
```

- `.block_addrs`: 해당 함수의 베이직 블록의 주소들
- `.blocks`: 해당 함수의 베이직 블록들(`capstone`)
- `.string_references()`: constant string의 리스트
- `.returning`: 함수가 return을 하는 지에 대한 정보
- `.callable`: 함수를 부를 수 있는 Python 함수로 만듦
- `.transition_graph`: 자신만을 포함하는 NetworkX DiGraph이다.
- `.has_unresolved_calls` or `.has_unresolved_jumps`: CFG의 정확성을 측정할 수 있다.
- `.get_call_sites()`: 다른 함수에서 불리면서 끝나는 basic block들의 주소 리스트
- `.get_call_target(callsite_addr)`: `callsite_addr`을 부르는 주소
- `.get_call_return(callsite_addr)`: `callsite_addr`이 return하는 주소

### CFGFast details
1. basic block이 VEX IR로 옮겨지고 exits(jumps, calls) 등이 모두 수집된다.
2. exit가 constant address일 경우, CFG에 edge로 추가되고, 또한 다음 목적지의 block을 추가한다.
3. 함수의 call 이벤트에서, 호출된 목적지의 block은 새로운 함수로 여겨지고 타겟 함수가 return할 경우, call 다음의 블록도 분석된다.
4. return 이벤트에서, 해당 함수는 returning으로 마크되고 적절한 edge가 CFG에 업데이트된다.
5. 모든 indirect jump에 Indirect Jump Resolution이 수행된다.

#### Finding function starts
심볼이 살아있는 바이너리에서는, 모든 함수의 심볼이 가능한 시작 지점을 찾을 수 있도록 사용된다.

심볼이 죽어있는 바이너리에서는, 바이너리의 아키텍처에 정의된 함수의 프롤로그 집합을 위하여 바이너리를 스캔한다.

#### FakeRets and function returns
처음에는 callee function이 return한다고 가정하여 그 다음 block을 caller function의 일부로 판단한다. 이를 "FakeRet"이라고 말하며 이것이 사실이 아닐 경우 "FakeRet"을 제거하고 CFG를 업데이트한다.

#### Options
- `force_complete_scan`: (Default: True)함수 탐지를 위해 바이너리 전체를 code로 다룬다. blob(code+data)의 경우 끄는게 좋다.
- `function_starts`: 분석에서 entry point로 쓰기 위한 address의 리스트이다.
- `normalize`: (Default: False) 결과 함수를 normalize한다.
- `resolve_indirect_jumps`: (Default: True) 모든 indirect jump를 찾기 위해 추가적인 분석을 수행한다.


### CFGEmulated details
#### Options
- `context_sensitivity_level`: (Default: 1)
- `starts`: 분석에서 entry point로 쓰기 위한 address의 리스트이다.
- `avoid_runs`: 분석에서 제외되는 주소의 집합
- `call_depth`: 이를 1로 설정함으로써 직접적으로 호출하는 특정 함수들을 판별해낼 수 있다.
- `initial_state`: CFG에 제공하는 초기 state
- `keep_state`: 메모리를 아끼기 귀하여 각 basic block의 state를 기본적으로 버린다.
- `enable_symbolic_back_traversal`
- `enable_advanced_backward_slicing`

### Backward Slicing
- **Required** CFGEmulated.
- **Required** Target. (backward slice가 종료할 목적지)
- **Optional** CDG. (CFG 파생)
- **Optional** DDG. (built on top of the CFG)

```py
>>> import angr
# Load the project
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})
# Generate a CFG first. In order to generate data dependence graph afterwards, you’ll have to
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs optio
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG
# recovery based on your needs.
>>> cfg = b.analyses.CFGEmulated(keep_state=True,
... state_add_options=angr.sim_options.refs,
... context_sensitivity_level=2)
# Generate the control dependence graph
>>> cdg = b.analyses.CDG(cfg)
# Build the data dependence graph. It might take a while. Be patient!
>>> ddg = b.analyses.DDG(cfg)
# See where we wanna go... let’s go to the exit() call, which is modeled as a
# SimProcedure.
>>> target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
>>> target_node = cfg.get_any_node(target_func.addr)
# Let’s get a BackwardSlice out of them!
# `targets` is a list of objects, where each one is either a CodeLocation
# object, or a tuple of CFGNode instance and a statement ID. Setting statement
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not
# have any statement, so you should always specify -1 for it.
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])
# Here is our awesome program slice!
>>> print(bs)
```

#### Using The `BackwardSlice` Object
- `runs_in_slice`(CFG-only): program slice에서 block의 주소와 SimProcedures를 보여주는 instance이다.
- `cfg_nodes_in_slice`(CFG-only): program slice에서 CFGNodes를 보여주는 instance이다.
- `chosen_statements`(with DDG): basic block 주소와 statement를 맵핑하는 dict이다.
- `chosen_exits`(with DDG): basic block 주소와 exits의 리스트를 맵핑하는 dict이다.

## Gotchas
### SimProcedure inaccuracy
symbolic execution을 더욱 추적 가능하게 하기 위해서 library function들은 `SimProcedure` python 함수로 쓰여지는데(또한 path explosion 방지), 이 함수는 정확하지 않아서 정확한 결과가 도출되지 않을 수도 있다. 이를 해결할 방법들은 다음과 같다.
1. `SimProcedure` 끄기(`Veritesting` 등을 통해서 path explosion을 완화시킬 수 있다.)
2. `SimProcedure`를 직접적으로 쓰는 무언가로 변경한다. 예를 들어, `scanf`의 경우 format string을 안다면, 이에 대한 hook을 작성할 수 있다.
3. `SimProcedure`를 고친다.

### Unsupported syscalls
System call도 `SimProcedure`로 개발되는데, 제대로 개발되지 않아서 이를 해결할 다음과 같은 방법들이 존재한다.
1. system call 개발
2. system call hook
3. `state.posix.queued_syscall_returns` 옵션을 사용하여 syscall return value를 queue 한다. 만약 return value가 queue 된다면, system call은 실행되지 않을 것이고, 값이 대신에 사용될 것이다.

### Symbolic memory model
만약 `read`의 memory index가 symbolic이고, 가능한 값의 범위가 너무 넓다면 index는 single value로 구체화 될 것이다. `write`도 동일하다. 이는 `state.memory`를 통한 memory concretization 전략을 사용함으로써 변경할 수 있다.

### Symbolic lengths
많은 경우에서, `read`나 `write`와 같은 함수의 length가 symbolic일 경우 이는 결국 실행의 마지막? 부분에서 구체화 될 것이다. 그렇지 않을 때에도, 소스나 목적지의 파일은 결국 이상하게 보일 것이다.

### Division by Zero
`Z3`가 division by zero에 대한 약간의 문제가 존재한다. 때문에 나눗셈을 진행할 때 division by zero를 방지하는 constraint를 넣어줘야 한다(denominator)

## General speed tips
- python 코드에 대한 jitting을 수행하는 pypy를 사용한다.
- `SimEngine` mixin을 필요할 때만 사용한다. (`SimEngine`의 기본 클래스인 `UberEngine`에서 필요 없는 선언들을 모두 제거한다.)
- shared library가 필요하지 않는 한 로드하지 않는다.
- hooking과 `SimProcedure`을 사용한다. 또한 문제가 발생하여 분석이 멈춘 부분을 hooking하여 이를 격리시킬 수도 있다.
- `SimInspect`를 사용한다. memory index resolution은 `angr`에서 가장 느린 부분 중의 하나인데, 이러한 행동을 hooking하거나 수정할 수 있다.
- concretization strategy를 작성한다. memory index resolution에 관한 가장 강한 해결책은 concretization strategy이다.
- `Replacement Solver`를 사용한다. symbolic data가 solve되는 순간에, symbolic data가 concrete data로 대체되어 실행 시간이 크게 줄어든다. 이 방법은 살짝 문제가 있지만, 도움이 될 것이다.

## If you're performing lots of concrete or partially-concrete execution
- unicorn engine을 사용한다.
- fast memory와 fast registers를 활성화한다. 이는 메모리 모델을 느슨하게 만들어 정확도를 희생하고 속도를 취할 것이다.
- 실행 전에 input 값을 concretize한다. 이는 `SimFile`을 이용하여 수행될 수 있다.

## The Emulated Filesystem
`SimFile`은 byte, symbolic 등의 순서를 정의하는 추상 저장소이다. 많은 종류의 `SimFile`들이 존재하고, 이들은 모두 저장하는 방법이 다르다. 간단한 예로 `SimFile(SimFileBase)`와 `SimPakcets`가 존재한다. 전자는 파일들을 다룰 때 사용되고, 후자는 stdin/stdout/stderr의 저장소로, short-reads, `scanf` 등에 사용된다.

### Example 1 Create a file with concrete content
```py
>>> import angr
>>> simfile = angr.SimFile('myconcretefile', content='hello world!\n')
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.blank_state()
>>> simfile.set_state(state)
>>> data, actual_size, new_pos = simfile.read(0, 5)
>>> import claripy
>>> assert claripy.is_true(data == 'hello')
>>> assert claripy.is_true(actual_size == 5)
>>> assert claripy.is_true(new_pos == 5)
>>> data, actual_size, new_pos = simfile.read(new_pos, 1000)
>>> assert len(data) == 1000*8 # bitvector sizes are in bits
>>> assert claripy.is_true(actual_size == 8)
>>> assert claripy.is_true(data.get_bytes(0, 8) == ' world!\n')
>>> assert claripy.is_true(new_pos == 13) 
```

### Example 2 Create a file with symbolic content and a defined size
```py
>>> simfile = angr.SimFile('mysymbolicfile', size=0x20)
>>> simfile.set_state(state)
>>> data, actual_size, new_pos = simfile.read(0, 0x30)
>>> assert data.symbolic
>>> assert claripy.is_true(actual_size == 0x20)
>>> assert simfile.load(0, actual_size) is data.get_bytes(0, 0x20)
```

### Example 3 Create a file with constrained symbolic content
```py
>>> bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(32)]
>>> bytes_ast = claripy.Concat(*bytes_list)
>>> mystate = proj.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=bytes_ast))
>>> for byte in bytes_list:
... mystate.solver.add(byte >= 0x20)
... mystate.solver.add(byte <= 0x7e)
```

### Example 4 Create a file with some mixed concrete and symbolic content, but no EOF
```py
>>> variable = claripy.BVS('myvar', 10*8)
>>> simfile = angr.SimFile('mymixedfile', content=variable.concat(claripy.BVV('\n')), has_end=
>>> simfile.set_state(state)
>>> assert claripy.is_true(simfile.size == 11)
>>> data, actual_size, new_pos = simfile.read(0, 15)
>>> assert claripy.is_true(actual_size == 15)
>>> assert claripy.is_true(new_pos == 15)
>>> assert claripy.is_true(data.get_bytes(0, 10) == variable)
>>> assert claripy.is_true(data.get_bytes(10, 1) == '\n')
>>> assert data.get_bytes(11, 4).symbolic
```

### Example 5 Create a file with a symbolic size ( has_end is implicitly true here
```py
>>> symsize = claripy.BVS('mysize', 64)
>>> state.solver.add(symsize >= 10)
>>> state.solver.add(symsize < 20)
>>> simfile = angr.SimFile('mysymsizefile', size=symsize)
>>> simfile.set_state(state)
>>> data, actual_size, new_pos = simfile.read(0, 30)
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(10, 20))
>>> assert len(data) == 30*8
>>> symreadsize = claripy.BVS('myreadsize', 64)
>>> state.solver.add(symreadsize >= 5)
>>> state.solver.add(symreadsize < 30)
>>> data, actual_size, new_pos = simfile.read(0, symreadsize)
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(5, 20))
```

### Example 6: Working with streams ( `SimPackets` )
```py
>>> simfile = angr.SimPackets('mypackets')
>>> simfile.set_state(state)
>>> data, actual_size, new_pos = simfile.read(0, 20, short_reads=True)
>>> assert len(data) == 20*8
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(21))
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>)]
>>> simfile.read(0, 1, short_reads=False)
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>), (<BV8 packet_1_mypackets>, <BV64
```

## Stdio streams
항상 state의 stdin `SimFile`을 `state.posix.stdin`으로 가져올 수 있다.
```py
>>> state.register_plugin('posix', angr.state_plugins.posix.SimSystemPosix(stdin=simfile, stdout=simfile, stderr=simfile)
>>> assert state.posix.stdin is simfile
>>> assert state.posix.stdout is simfile
>>> assert state.posix.stderr is simfile
```
혹은 더욱 간단하게 작성할 수도 있다.
```py
>>> state = proj.factory.entry_state(stdin=simfile)
>>> assert state.posix.stdin is simfile
```

## Intermediate Representation
각기 다른 architecture에서 실행하는 코드를 분석하기 위하여 `angr`는 VEX IR을 사용한다.
- `Register names.`: 현대의 CPU는 일반적인 목적의 레지스터들과, stack pointer, condition flag register 등의 흔한 설계를 갖고 있다. VEX는 integer offset으로 구분하여 각기 다른 메모리 공간에 레지스터를 표현한다. (AMD64의 `rax`는 메모리 공간 16에 저장된다.)
- `Memory access.`: 각기 다른 방법으로 메모리에 접근한다.(LE, BE)
- `Memory segmentation.`: x86과 같은 아키텍처들은 segment register를 통해서 memory segmentation을 지원하는데, IR은 이를 이해한다.
- `Instruction side-effects.`: 대부분의 명령어들은 side-effects를 갖고 있는데, 대표적으로 ARM의 thumb mode가 condition flag를 업데이트 하는 것과 push/pop 명령이 rsp를 바꾸는 것이 있다. 이를 자동으로 처리하기는 미친 짓이기 때문에 IR은 이러한 side-effects를 명시적으로 관리한다.

## Claripy ASTs
- BV
  - `claripy.BVS('x', 32)`
  - `claripy.BVV(0xc001b3475, 32)`
  - `claripy.SI(name = 'x', bits=32, lower_bound=000, upper_bound=000, stride=10)`
- FS
  - `claripy.FPS('b', claripy.fp.FSORT_DOUBLE)`
  - `claripy.FPV(3.2, claripy.fp.FSORT_FLOAT)`
- Bool
  - `claripy.BoolV(True)` or `claripy.true` or `claripy.false`

- `claripy.LShR(x, 10)`
- `claripy.SignExt(32, x)` or `x.sign_extend(32)`
- `claripy.ZeroExt(32, x)` or `x.zero_extend(32)`
- `claripy.Extract(7, 0, x)` or `x[7:0]`
- `claripy.Concat(x, y, z)`
- `claripy.RotateLeft(x, 8)`
- `claripy.RotateRight(x, 8)`
- `claripy.Reverse(x)` or `x.reversed`
- `claripy.And(x == y, x > 0)`
- `claripy.Or(x == y, y < 10)`
- `claripy.Not(x == y)` is the same as `x != y`
- `claripy.If(x > y, x, y)`
- `claripy.ULE(x, y)`
- `claripy.ULT(x, y)`
- `claripy.UGE(x, y)`
- ~~

Python의 `>`, `<` 등은 Claripy에서 unsigned이다. 하지만 z3에서는 이는 signed이다.

## Solvers
- `Solver`: `z3.solver`와 비슷하다.
- `SolverVSA`: 실제 constraint solve를 진행하지 않고 `VSA`를 수행하여 값을 추정한다.
- `SolverReplacement`: 실행 중에 expression을 replace한다.
- `SolverHybrid`: SolverReplacement와 VSA, Z3 Solver를 합쳐 값을 추정한다.
- `SolverComposite`: 작은 조건의 조합들을 해결하여 조건 해결 속도를 높인다.
```py
# create the solver and an expression
>>> s = claripy.Solver()
>>> x = claripy.BVS('x', 8)
# now let's add a constraint on x
>>> s.add(claripy.ULT(x, 5))
>>> assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
>>> assert s.max(x) == 4
>>> assert s.min(x) == 0
# we can also get the values of complex expressions
>>> y = claripy.BVV(65, 8)
>>> z = claripy.If(x == 1, x, y)
>>> assert sorted(s.eval(z, 10)) == [1, 65]
# and, of course, we can add constraints on complex expressions
>>> s.add(z % 5 != 0)
>>> assert s.eval(z, 10) == (1,)
>>> assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1
```