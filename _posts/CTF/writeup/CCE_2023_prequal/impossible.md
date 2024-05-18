# ☠️ impossible
> golang + wails를 통해 구현한 GUI 앱에서 ID와 PASSWORD를 크랙해야 하는 문제

## Analysis
`IDA 8.3`을 이용하여 golang을 디스어셈블 하였다.
`IDA 7.5`이상의 버전에서 `AlphaGolang`을 사용하여 .gopclntab을 복구하고 디맹글링을 진행해도 되지만, `go 1.13` 이상의 버전에서 함수 호출규약이 변경되었기 때문에
> 기존 스택 기반 인자 전달 방법에서 레지스터 기반 인자 전달 방식(RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11, STACK)으로 변경

최신 버전의 디스어셈블러를 사용하는 것이 수고를 줄일 수 있다.

`main_main` 함수에서 `wails` 관련 설정을 진행하고, `main__ptr_App_startup` 함수를 시작 함수에 등록한다.
이 외의 `main_PPtr_App_Greet` 함수를 등록하는 부분은 찾아볼 수 없었지만 이 곳 말고 분석할 곳이 없었기에 먼저 분석을 시작하였다.

최신 버전의 디스어셈블러를 사용하여도 인자 개수 및 변수 타입 등이 뒤죽 박죽이어서 이 부분들을 모두 해결하고 난 후, `golang`의 특성을 생각해주면서 함수를 분석해주면 된다.
> PE를 Go Runtime이 감싸고 있는 구조기 때문에, golang에서 사용하는 대부분의 feature가 함수처럼 사용된다.
> 
> buf := make([]string, 0)
> 
> buf.append(1)
> 
> ↓
>
> __int64 buf
> 
> runtime_growslice(buf.ptr, buf.len, buf.cap, 1)
>
> *buf = 1

`Greet` 함수에서 탑다운 방식으로 분석을 진행하다 보면, ID와 PASSWORD를 검사하는 함수들이 바로 보인다.
전체적으로 `P-BOX`와 `S-BOX`를 이용하여 암호화를 진행하고, 각 바이트가 서로에게 영향을 끼치지 않고, 각각 독립적으로 암호화된다. 

즉, 한 바이트 씩 알아낼 수 있다.

ID 검사 함수의 pseudo code는 아래와 같다.
```py
def find_id(myid) -> bytes:
    pBox = bytes.fromhex('02 04 0e 0c 0f 0d 01 0a 08 06 07 05 0b 03 09 00')
    sBox = bytes.fromhex('79 80 7a 70 1f 15 15 8b ef f5 54 22 b6 3f 05 61')
    target = bytes.fromhex('90 3c 13 72 15 96 24 7e cd 19 62 26 28 d1 55 10')

    myid_duff1 = b""
    myid_duff2 = b""

    for d in pBox:
        myid_duff1 += bytes([myid[d]])
    
    for i, j in zip(myid_duff1, sBox):
        myid_duff2 += bytes([i ^ j])
    
    v34 = substitution_duff2(myid_duff2)

    if v34 == target:
        return myid
    else:
        return None

def substitution_duff2(sBox):
    v8 = b""
    v17 = b""

    for d in sBox:
        v8 += bytes([(d >> 4) & 0xF | ((0x10 * d) & 0xFF)]) # ROR4
    
    for idx in range(0x10):
        if (idx & 3) != 0:
            v23 = idx - 4 * (idx >> 2)

            if v23 == 1:
                v17 += bytes([v8[idx] ^ 0x11])
            elif v23 == 2:
                v17 += bytes([v8[idx] ^ 0x22])
            else:
                v17 += bytes([v8[idx] ^ 0x33])
        else:
            v17 += bytes([v8[idx]])

    return v17
```
전체적으로 사칙연산 및 비트연산을 사용하기 때문에 역연산이 가능하다. 올바른 ID가 되려면 `substitution_duff2` 함수의 리턴 값인 `v17`이 `target`과 같아야 된다는 점을 이용하여, 위 과정을 순서대로 나열한 후, 다시 반대로 진행해주면 된다.

PW 검사 함수도 비슷하다. 하지만 계산 중간 중간에 입력한 PW 값이 사용되기 때문에 역연산이 불가능하다.

이는 한 바이트 씩 암호화가 된다는 점을 이용하면 된다. bruteforce로 한 바이트 씩 알아낼 수 있다.

또 알아야 할 점으로는 아래의 코드를 보자.
```py
v25 = 3 * (idx + ((idx * 0xAAAAAAAAAAAAAAAB) >> 64) // 2)
if idx == v25:
    pass
```
`v25`의 계산식은 최적화를 통해 mod 연산이 변한 모습이다. 특징점이라고 할 수 있는 `0xAAAAAAAAAAAAAAAB` 값을 구글링하면 `idx == v25` 식은 결국 `idx % 3 == 0`과 같다는 점을 알 수 있다.

## Entire Crack Code
```py
import string
from itertools import permutations
import hashlib
import multiprocessing as mp

# myid = b"myidmyidmyidmyid"

def find_pw() -> str:
    pass

def substitution_duff2(sBox):
    v8 = b""
    v17 = b""

    for d in sBox:
        v8 += bytes([(d >> 4) & 0xF | ((0x10 * d) & 0xFF)])
    
    for idx in range(0x10):
        if (idx & 3) != 0:
            v23 = idx - 4 * (idx >> 2)

            if v23 == 1:
                v17 += bytes([v8[idx] ^ 0x11])
            elif v23 == 2:
                v17 += bytes([v8[idx] ^ 0x22])
            else:
                v17 += bytes([v8[idx] ^ 0x33])
        else:
            v17 += bytes([v8[idx]])

    return v17

def substitution_duff2_reverse(target):
    v17 = target
    v8 = b""
    myid_duff2 = b""

    for idx in range(0x10):
        if (idx & 3) != 0:
            v23 = idx - 4 * (idx >> 2)

            if v23 == 1:
                v8 += bytes([v17[idx] ^ 0x11])
            elif v23 == 2:
                v8 += bytes([v17[idx] ^ 0x22])
            else:
                v8 += bytes([v17[idx] ^ 0x33])
        else:
            v8 += bytes([v17[idx]])
    
    for _v8 in v8:
        for d in range(256):
            if _v8 == ((d >> 4) & 0xF | ((0x10 * d) & 0xFF)):
                myid_duff2 += bytes([d])
    
    return myid_duff2
            
def find_id(myid) -> bytes:
    pBox = bytes.fromhex('02 04 0e 0c 0f 0d 01 0a 08 06 07 05 0b 03 09 00')
    sBox = bytes.fromhex('79 80 7a 70 1f 15 15 8b ef f5 54 22 b6 3f 05 61')
    target = bytes.fromhex('90 3c 13 72 15 96 24 7e cd 19 62 26 28 d1 55 10')

    myid_duff1 = b""
    myid_duff2 = b""

    for d in pBox:
        myid_duff1 += bytes([myid[d]])
    
    for i, j in zip(myid_duff1, sBox):
        myid_duff2 += bytes([i ^ j])
    
    v34 = substitution_duff2(myid_duff2)

    if v34 == target:
        return myid
    else:
        return None

def find_id_reverse():
    pBox = bytes.fromhex('02 04 0e 0c 0f 0d 01 0a 08 06 07 05 0b 03 09 00')
    sBox = bytes.fromhex('79 80 7a 70 1f 15 15 8b ef f5 54 22 b6 3f 05 61')
    target = bytes.fromhex('90 3c 13 72 15 96 24 7e cd 19 62 26 28 d1 55 10')

    myid_duff1 = b""
    myid = [0]*16

    myid_duff2 = substitution_duff2_reverse(target)

    for i, j in zip(myid_duff2, sBox):
        myid_duff1 += bytes([i ^ j])
    
    for i, d in enumerate(pBox):
        myid[d] = bytes([myid_duff1[i]])

    return b"".join(myid)

def substitution_pw_reverse(digest, sBox, target):
    v50 = b""
    mypw = ""

    for idx in range(0x10):
        for ch in string.printable.encode():
            v14 = digest[idx]
            v15 = ch
            v16 = sBox[v14 ^ v15]
            v17 = digest[idx + 16]
            v18 = v17 ^ ~ch
            v19 = sBox[v18]
            v20 = ch ^ v17
            v21 = (v20 + v14) & 0xFF
            v22 = sBox[v21]
            v25 = 3 * (idx + ((idx * 0xAAAAAAAAAAAAAAAB) >> 64) // 2)
            # if idx == v25:
            if idx % 3 == 0:
                v50 = (v16 ^ v19 ^ v22) & 0xFF
            else:
                # if idx - v25 == 1:
                if idx % 3 == 1:
                    v50 = (~v16 ^ v19 ^ (v22 + 1)) & 0xFF
                else:
                # if idx % 3 == 2:
                    v50 = (v19 + v16 - v22) & 0xFF

            if v50 == target[idx]:
                mypw += chr(ch)
                break
            else:
                pass
                # print(v50, target[idx])
        # print(v25)
    return mypw

def find_pw(myid):
    sBox = bytes.fromhex('10 C0 57 19 87 CF F2 7D EA 8D 65 CB 78 FE 60 61 2C 86 8E EB 7F A9 E5 CD 75 06 4E D5 F4 C9 02 C1 22 38 39 3C CE 09 98 EF 40 BC FA 3F 05 50 E9 2A 70 C2 A1 67 FB BE 99 73 E2 1E 6B 41 7A 97 92 8F 84 D3 81 E0 30 79 7C D6 6A EE E7 B4 16 B0 54 D7 DC A0 AA 47 F3 63 ED 35 27 28 F6 34 1C B1 DE 95 01 5C 4A 1F 8A DD BB 96 F8 C6 4D DF 6F F0 17 2F E4 2E CC 04 76 7B 43 56 88 D0 6E 4C F9 64 E6 A3 74 1B 5E 62 D9 0F 7E C7 DA FF D4 5B 9F 0B F1 1D 2B 66 C3 08 C5 11 5F A6 C4 82 B7 B3 E8 55 B5 9C CA 42 29 AD 45 6D 21 9E 44 49 E3 AC 24 71 00 A2 90 4F E1 23 FC 26 6C 33 77 48 AE D2 46 31 93 0E 37 B9 18 F5 59 9B 4B F7 BD A5 BF 58 91 BA FD 13 89 B6 52 1A D8 53 A8 68 2D DB 83 32 EC C8 36 A4 B2 5A 94 AB 25 3B 8C 51 3E A7 03 15 07 72 14 80 69 3D 85 9D 20 0C B8 AF 8B 0D 12 3A 9A 5D 0A D1')
    target = bytes.fromhex('15 0c df fc 6a 19 0b 0d 18 d0 c4 de 64 50 d1 c3')
    sha = hashlib.sha256(myid)
    digest = bytes.fromhex(sha.hexdigest())

    # mypw = b"aaaabbbbccccdddd"
    # v50 = substitution_pw(mypw, digest.encode(), sBox)
    mypw = substitution_pw_reverse(digest, sBox, target)

    return mypw

_string = permutations(string.printable, 16)

def mp_func(i):
    for myid in _string:
        _myid = ''.join(myid[::-1]).encode()
        # print(_myid)
        goal = find_id(_myid)
        
        if goal:
            print(goal)
            break

if __name__ == "__main__":
    # p = mp.Pool(4)

    # p.map(mp_func, [1, 2, 3, 4])

    # p.close()
    # p.join()

    myid = find_id_reverse()
    print(myid.decode())
    print(find_pw(myid))
```