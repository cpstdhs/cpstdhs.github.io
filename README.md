# 🥇 FOR FUTURE
> 공부 목록 정리


# Catalog
- [🥇 FOR FUTURE](#-for-future)
- [Catalog](#catalog)
- [Study Flow](#study-flow)
  - [Python](#python)
  - [C++](#c)
  - [System programming](#system-programming)
  - [Windows api](#windows-api)
  - [C#](#c-1)
  - [Powershell](#powershell)
  - [Blockchain](#blockchain)
  - [OS](#os)
  - [Static Analysis](#static-analysis)
  - [Fuzzer Anlaysis](#fuzzer-anlaysis)
  - [Dynamic Analysis](#dynamic-analysis)
  - [Static Binary Instrumentation](#static-binary-instrumentation)
  - [Dynamic Binary Instrumentation](#dynamic-binary-instrumentation)
  - [Disassembler](#disassembler)
  - [Ctf](#ctf)
  - [1-day](#1-day)
  - [Bug Bounty](#bug-bounty)
  - [Certificate](#certificate)
  - [etc](#etc)
  - [white paper](#white-paper)

# Study Flow
- Bug hunting(`1-day`): [Disassembler](#disassembler), [C++](#c) → [System programming](#system-programming) → [Windows api](#windows-api) → [1-day](#1-day), [C#](#c-1), [Powershell](#powershell), [Os](#os)

- Bug hunting(`fuzzer`): [C++](#c) → [System programming](#system-programming) → [Windows api](#windows-api) → [Static Analysis](#static-analysis), [Dynamic Analysis](#dynamic-analysis), [Static Binary Instrumentation](#static-binary-instrumentation), [Dynamic Binary Instrumentation](#dynamic-binary-instrumentation) → [Fuzzer Analysis](#fuzzer-anlaysis)

- CTF: [Python](#python) → [Dynamic Analysis](#dynamic-analysis) → [Ctf](#ctf)

- Bug hunting & CTF: [Blockchain](#blockchain)

- Certificate: [정보보안기사 실기](#정보보안기사-실기)

CTF → Bug hunting(`1-day`) → Bug hunting(`fuzzer`)

---

## Python
- [x] [python](python/python.md)(`docs`)

## C++
- [x] [모두의 코드 씹어먹는 c++](c++/c++.md)(`pdf`)
- [x] effective c++(`book`)
- effective modern c++(`book`)

## System programming
- [x] 뇌를 자극하는 윈도우즈 시스템 프로그래밍(`book`)

## Windows api
- [x] Windows API 정복1(`book`)
- [x] Windows API 정복2(`book`)


## C#
- [x] 이것이 c#이다(`book`)


## Powershell
- [ ] [powershell](https://learn.microsoft.com/ko-kr/powershell/)


## Blockchain
- [x] [cryptozombies](blockchain/cryptozombies/cryptozombies.md)(`web`)
- [x] [ethernaut](blockchain/vulnerability/vulnerability.md)(`pdf`)
-  Mastering Ethereum(`book`)


## OS
- [x] c++로 나만의 운영체제 만들기(`book`)
- [ ] kaist os(`pdf`)
- [ ] Windows Internals Vol.07(`pdf`)


## Static Analysis
- [ ] clang(`pdf`)
- [ ] codeql(`pdf`)
- [ ] weggli(`pdf`)


## Fuzzer Anlaysis
- [x] winafl(`github`)
- [ ] winfuzz(`github`)


## Dynamic Analysis
- [x] [z3](dynamic_analysis/z3/z3.md)(`pdf`)
- [x] [angr](dynamic_analysis/angr/angr.md)(`pdf`)
- [x] [more_angr](dynamic_analysis/angr/more_angr.md)(`pdf`)


## Static Binary Instrumentation
- [ ] Dyninst(doesn't need symbol)(`pdf`)
- PEBIL(need symbol)(`pdf`)


## Dynamic Binary Instrumentation
- [ ] dynamorio(`pdf`)
- [ ] llvm(`pdf`)


## Disassembler
- [x] Windows Debugging 2/e(`book`)
- [x] 리버싱 핵심 원리(`book`)
- [x] [ida](disassembler/ida/ida.md)(`pdf`)
- ghidra(`pdf`)


## Ctf
- [x] 공군 정보통신 경연대회 최우수상
- [x] 2023 whitehat contest military track final 4th(`(주)공군`)
- [x] 2023 CCE final 8th(`썽조보유팀`)
- [x] 공군 사이버전사 경연대회 우수상
- [x] 2022 whitehat contest military track prequal 20th(`어니언-조각치킨`)
- [some ctf things]()
- [web tips](CTF/CTF_TIPS/web.md)
- [pwnable tips](CTF/CTF_TIPS/pwn.md)
- [reversing tips](CTF/CTF_TIPS/rev.md)
- [crypto tips](CTF/CTF_TIPS/crypto.md)
- [forensic tips](CTF/CTF_TIPS/forensic.md)
- [misc tips](CTF/CTF_TIPS/misc.md)


## 1-day
- [1day Analysis](1day/1day.md)
- [cve repo](https://github.com/trickest/cve)(`github`)
- [itm4n](https://itm4n.github.io/)(`blog`)
- [project-zero](https://googleprojectzero.blogspot.com/)(`blog`)
- [exploit-db](https://www.exploit-db.com/)(`blog`)

## Bug Bounty
- [x] 2020 금융권 하반기 버그바운티 수상
- [x] 2020 금융권 상반기 버그바운티 수상

## Certificate
- [x] 2023 알기사 정보보안기사 실기
- [ ] [TOEIC® Speaking Test](Certificate/TOEIC_Speaking.md)

## etc
- [ ] [coding test](coding_test)
- [ ] [regex](etc/regex/regex.md)
- [x] [docker](etc/docker/docker.md)


## white paper
- [x] [(State of) The Art of War: Offensive Techniques in Binary Analysis](white_paper/The_Art_of_War.md)
- [ ] [The Art, Science, and Engineering of Fuzzing: A Suvery]()
- [ ] [Grey-box Concolic Testing on Binary Code]()
- [ ] [Fight against 1-day exploits: Diffing Binaries vs Anti-diffing Binaries]()
- [ ] [A Survey of Binary Code Similarity]()