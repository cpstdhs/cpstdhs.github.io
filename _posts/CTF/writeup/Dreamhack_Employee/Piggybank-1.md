# Piggybank-1
## Overview
springboot를 이용하여 jar 형태로 배포된 가상의 은행 웹서비스이다.

admin의 비밀번호를 변경하는 것이 목표로 보인다.
이를 위해 맨 처음 의심한 부분은 race-condition 취약점이다:
`UserPasswordResetService:doChallenge:`
```java
            if (canLock(challengeToken)) {
                Object obj2 = this.redis.get(getCHALLENGE_INDEX_PREFIX() + ":" + challengeToken);
                if (obj2 == null || (obj = obj2.toString()) == null || (split$default = StringsKt.split$default((CharSequence) obj, new String[]{","}, false, 0, 6, (Object) null)) == null) {
                    throw new UserServiceException("challenge 코드가 만료되었습니다.");
                }
                Iterable $this$map$iv = split$default;
                Collection destination$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv, 10));
                for (Object item$iv$iv : $this$map$iv) {
                    String it = (String) item$iv$iv;
                    destination$iv$iv.add(Integer.valueOf(Integer.parseInt(it)));
                }
                List<Number> challengeIndex = (List) destination$iv$iv;
                Object obj3 = this.redis.get(getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken);
                if (obj3 == null || (userName = obj3.toString()) == null) {
                    throw new UserServiceException("challenge token이 만료되었습니다.");
                }
                User userInfo = this.userRepository.findUserByUsername(userName);
                if (userInfo == null) {
                    throw new UserServiceException("예상치 못한 에러가 발생 했습니다.");
                }
                List userSecureCode = StringsKt.split$default((CharSequence) userInfo.getSecureCode(), new String[]{","}, false, 0, 6, (Object) null);
                int rateLimitCount = getRateLimit(challengeToken);
                Thread.sleep(8000L);
                checkRateLimit(rateLimitCount);
                int i = 0;
                for (Number number : challengeIndex) {
                    int index = i;
                    i++;
                    int challIndex = number.intValue();
                    if (!Intrinsics.areEqual(userSecureCode.get(challIndex - 1), answer.get(index))) {
                        setRateLimit(challengeToken, rateLimitCount + 1);
                        throw new UserServiceException("올바르지 않은 secure code 입니다. 실패 횟수: " + (rateLimitCount + 1));
                    }
                }

```
내부 redis 데이터베이스로부터 rateLimitCount를 가져오고, 해당 값이 7 이상이 되면 비밀번호를 초기화시킬 수 없다.
하지만 getRateLimit과 setRateLimit 사이에 Thread.sleep(8000)이 존재하기 때문에 rateLimit이 0일 때 여러 요청을 발생시켜 여러 번 비밀번호 초기화 challenge를 수행할 수 있을 줄 알았다.
하지만 canLock 함수를 통해 database lock이 구현되어 있었다.
해당 값도 변조가 가능할 것 같지만 내가 가지고 있는 정보로는 불가능했다:
```
rateLimit -> CONFIG:username
lock -> CONFIG:LOCK:userId
```
위 정보를 통해 username을 LOCK:userId로 바꾸면 lock을 임의로 해제할 수 있을 것이라 생각했지만 userId를 알아낼 방법을 찾아낼 수 없었다.

위 방법은 추후로 밀어놓고, 다른 부분을 찾기 시작했다.
다음은 유저를 생성하는 로직이다:
`UserService:createUser:`
```java
        Object save = this.userRepository.save(new User(username, hashedPassword, email, realName, memo, regNumber, countryCode, null, 128, null));
        Intrinsics.checkNotNullExpressionValue(save, "save(...)");
        User newUser = (User) save;
        String newSecureCode = createSecureCode(newUser.getId());
```
보안 코드를 생성하는 함수를 살펴보다 보면, 보안 코드 리스트를 확인할 수 있다:
```
 @NotNull
 private static final List<String> SECURE_CODE_LIST = CollectionsKt.mutableListOf("refuse", "sector", "dentist", "release", "tenant", "lunch", "code", "partner", "chicken", "ribbon", "apple", "cargo", "damage", "enjoy", BeanDefinitionParserDelegate.INDEX_ATTRIBUTE, "theori", "dreamhack", "across", "idea", "noble");
private static final int SECURE_CODE_INDEX = 2;
```
위 보안 코드 리스트 중 2개의 값만 선택하여 비밀번호 변경 시 사용된다.
일반적으로 사용하는 보안 카드를 떠올려 봤을 때, 매우 적은 값이라고 생각됐다.

## Solution
secure code의 개수와 인증에 필요한 단어의 개수가 매우 적기 때문에 가능한 단어의 조합은 총 380개밖에 되지 않으며, 7번 시도할 수 있기 때문에 약 1.8% 확률로 brute force가 가능하다.
또한, `Piggybank-1`과 `Piggybank-2`의 가상 인스턴스를 돌아가며 계속해서 발급받을 수 있어 내부 비밀번호 찾기 제한 값인 `CONFIG:admin`를 계속해서 초기화시킬 수 있다.

위 내용을 토대로 반복적으로 비밀번호 찾기를 수행하다 보면 passResetToken을 발급받을 수 있다:
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/ed401e2429ce89cb2c692620f7e565ffd13f9415ac869d805093e5514ed8a8bc.png)

해당 링크로 접속하여 패스워드를 변경하고 admin으로 접속하여 마이페이지를 확인해보면 flag가 존재한다:
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/47c1803557c87dd18e39e0d159c171bf18b9f05f4c6dc0db3b3796f0e9f81958.png)