# ✍️ REV CTF TIPS
> 참고할만한 reversing 팁들을 기록

# Catalog
- [✍️ REV CTF TIPS](#️-rev-ctf-tips)
- [Catalog](#catalog)
  - [Search Memory on gdb-peda](#search-memory-on-gdb-peda)
  - [Handle signal in gdb](#handle-signal-in-gdb)
  - [Fork problem in gdb](#fork-problem-in-gdb)
  - [Multithread in gdb](#multithread-in-gdb)
  - [Bit Rotation](#bit-rotation)
    - [ROL, ROR](#rol-ror)
  - [Play With Hex](#play-with-hex)
    - [bytes](#bytes)
    - [bytearray](#bytearray)
    - [int](#int)
    - [hex](#hex)
  - [Inverse operation](#inverse-operation)
  - [Bitwise Operation](#bitwise-operation)
    - [Get the maximum integer](#get-the-maximum-integer)
    - [Check Equality](#check-equality)
    - [Check if number is odd](#check-if-number-is-odd)
  - [Fixed point \&\& Floating point](#fixed-point--floating-point)
    - [Binary system](#binary-system)
    - [Fixed point](#fixed-point)
    - [Floating point](#floating-point)
      - [Normalization](#normalization)
      - [Set bit](#set-bit)
    - [Fixed point vs Floating point](#fixed-point-vs-floating-point)
  - [Simd: sse / avx](#simd-sse--avx)

## Search Memory on gdb-peda
```sh
searchmem "string"
searchmem $address
```

## Handle signal in gdb
```sh
handle [SIGNUM] [stop/print/pass]
```
## Fork problem in gdb
```sh
default, gdb: parent, gdb-peda: child
set follow-fork-mode parent
set follow-fork-mode child
set detach-on-fork off
    info inferiors
    inferior x
```

## Multithread in gdb
```
break [addr] thread [threadno]
set scheduler-locking on
thread apply [all/no] bt
```

## Bit Rotation
### ROL, ROR
```py
def __ROL4__(num, count, bits=32):
    num &= 0xFFFFFFFF
    return ((num << count) | (num >> (bits - count))) & ((0b1<<bits) - 1)

def __ROR4__(num, count, bits=32):
    num &= 0xFFFFFFFF
    return ((num >> count) | (num << (bits - count))) & ((0b1<<bits) - 1)
```

## Play With Hex
### bytes
```py
bytes.fromhex('2Ef0 F1f2 ')
b'.\xf0\xf1\xf2'
```
```py
value = b'\xf0\xf1\xf2'
value.hex('-')
'f0-f1-f2'
b'UUDD'.hex()
'55554444'
```
### bytearray
```py
bytes와 동일
```
### int
```py
(1024).to_bytes(2, byteorder='big')
b'\x04\x00'
(-1024).to_bytes(10, byteorder='big', signed=True)
b'\xff\xff\xff\xff\xff\xff\xff\xff\xfc\x00'
```
```py
int.from_bytes(b"\x00\x10", byteorder='big')
16
int.from_bytes(b"\xfc\x00", byteorder='big', signed=True)
-1024
```
### hex
```py
i = 3735928559
f'{i:x}'
'deadbeef'
hex(i)[2:]
'deadbeef
```

## Inverse operation

## Bitwise Operation
### Get the maximum integer
```py
(1 << 31) - 1 # 4byte maximum
~(1 << 31)
```
### Check Equality
```py
(a^b) == 0
!(a^b) == 0
```
### Check if number is odd
```py
(n & 1) == 1
```
## Fixed point && Floating point
### Binary system
```py
13.625 == 0b1101.101 (8+4+0+1.1/2+0+1/8)
=> 0b01101.1010000000..
```
### Fixed point
```
- 부호 비트 / 정수부 / 소수부
- 정수부는 뒤에서부터 채우고, 소수부는 앞에서부터 채움
```

### Floating point
```
- 부호 비트 / 지수부 / 가수부
- 32bit bias: 127
- 64bit bias: 1023
```
#### Normalization
```
1.xx.. * 2^n
```
위 형태의 식으로 `Normalization`
```py
0b1101.101 -> 0b1.101101 * 2^3
```
#### Set bit
```
지수부 = 127(bias) + 3(지수) == 130 == 0b10000010
가수부 = 0b101101
=> 0b010000010.0b1011010000000000..
```

### Fixed point vs Floating point
```
Fixed Point의 경우 정수/소수로 나누어 값을 표현하기 때문에 값의 범위가 적다, 하지만 이 특성으로 인하여 실수를 정수와 같이 계산할 수 있기 떄문에 오버헤드를 줄일 수 있다.
```
```
Floating Point의 경우 지수부/가수부로 나누어 값을 표현하기 때문에 보다 큰 수까지 다룰 수 있다.
```


## Simd: sse / avx
