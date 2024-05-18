# 😡 pair_worker
> 부모 프로세스에서 자식 프로세스를 ptrace로 디버깅 및 값을 세팅하며 관리하는 프로그램

- [😡 pair\_worker](#-pair_worker)
  - [Analysis](#analysis)
    - [POINT 1](#point-1)
    - [POINT 2](#point-2)
    - [POINT 3](#point-3)
    - [POINT 4](#point-4)
  - [Exploit Code](#exploit-code)

## Analysis
### POINT 1
ptrace의 `PTRACE_POKEDATA` 옵션은 8바이트를 기준으로 값을 설정한다. 하지만 **바이너리에서는 1바이트를 기준인 것 처럼 값을 설정**하고 있어 7바이트 오버플로우 발생 -> `Fake RBP` 가능
### POINT 2
**1000 바이트 메모리 버퍼를 초기화하지 않고 복사**하여 사용자에게 출력해주고 있다. -> `leak` 가능
### POINT 3
bss 영역에 값을 입력받고 쉘코드를 실행시켜야 하지만 가젯이 부족하다. 아래의 가젯들을 이용하여 세팅이 가능하다.
- pop rbp
- lea rax, [rbp]
- mov QWORD PTR [rbp - 0x8], rax
- lea rdi, [rbp+var_buf]; call <입력함수>
### POINT 4
함수 프롤로그의 `sub, rsp, 0x3F0` 명령을 이용하여 공격 코드가 들어갈 공간을 확보 후, 해당 bss 영역으로 return하여 쉘코드를 실행시킨다.

## Exploit Code