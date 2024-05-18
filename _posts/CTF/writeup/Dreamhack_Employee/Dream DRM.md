# Dream DRM
## OverView
`DRM(Digital Rights Management)` 기술을 접목시킨 일종의 eBook 안드로이드 앱이다.

내부에서 사용하는 코드 조각들을 구글링해보면, `retrofit` 라이브러리를 이용하여 웹 통신을 구현하고 있음을 추측할 수 있다.

초기 화면에서 go를 누르면 아래 함수가 실행된다.
`e4.h.onClick:`
```java
                Integer[] v7_1 = new Integer[16];
                v7_1[0] = Integer.valueOf(0xF2);
                v7_1[1] = Integer.valueOf(90);
                v7_1[2] = Integer.valueOf(0xB6);
                v7_1[3] = Integer.valueOf(0x7E);
                v7_1[opCode] = Integer.valueOf(98);
                v7_1[5] = Integer.valueOf(130);
                v7_1[6] = Integer.valueOf(73);
                v7_1[7] = Integer.valueOf(0x9E);
                v7_1[8] = Integer.valueOf(0xB3);
                v7_1[9] = Integer.valueOf(0xE4);
                v7_1[10] = Integer.valueOf(0xFC);
                v7_1[11] = Integer.valueOf(0x77);
                v7_1[12] = Integer.valueOf(74);
                v7_1[13] = Integer.valueOf(45);
                v7_1[14] = Integer.valueOf(0xA9);
                v7_1[15] = Integer.valueOf(0x7F);
                m v6_1 = new m(v.ToList(((Object[])v7_1)));
                String v7_2 = ((Context)main).getString(0x7F0F00BF);
                o.IsNull(v7_2, "getString(R.string.user_agent)");
                v4_1.a("User-Agent", v6_1.a(v7_2));
                v7_1 = new Integer[16];
                v7_1[0] = Integer.valueOf(0xA1);
                v7_1[1] = Integer.valueOf(0xEF);
                v7_1[2] = Integer.valueOf(0xD7);
                v7_1[3] = Integer.valueOf(17);
                v7_1[opCode] = Integer.valueOf(0xE3);
                v7_1[5] = Integer.valueOf(0xD7);
                v7_1[6] = Integer.valueOf(0xB7);
                v7_1[7] = Integer.valueOf(0x81);
                v7_1[8] = Integer.valueOf(55);
                v7_1[9] = Integer.valueOf(0x7B);
                v7_1[10] = Integer.valueOf(66);
                v7_1[11] = Integer.valueOf(109);
                v7_1[12] = Integer.valueOf(0x93);
                v7_1[13] = Integer.valueOf(0xFD);
                v7_1[14] = Integer.valueOf(60);
                v7_1[15] = Integer.valueOf(1);
                v6_1 = new m(v.ToList(((Object[])v7_1)));
                v3 = ((Context)main).getString(0x7F0F001E);
                o.IsNull(v3, "getString(R.string.authorization)");
                v4_1.a("Authorization", v6_1.a(v3))
```
서버에 접속할 때, 헤더 정보들을 설정해주는데 난독화 되어있어 직접 요청을 보내기 위해서는 해당 난독화를 해제하여야 한다.

접속 후에는 RecyclerView를 이용하여 화면에 책 정보를 나열하는데, 해당 동작은 RecyclerAdapter의 onClickListener에서 이루어진다.
탑다운 방식으로 쭉 분석하다 보면, pdf를 서버로부터 받아와 복호화 후 클라이언트에 보여주는데, 이는 JNI를 통해 구현되어 있다.
`com.theori.dreamdrm.MainActivity:`
```java
    public final native boolean decrypt(String arg1, String arg2) {
    }
```
`e4.b:`
```java
        String v7_1 = this.c.a();
        String v8_2 = v2.getAbsolutePath();
        o.IsNull(v8_2, "file.absolutePath");
        if(!v1_1.decrypt(v8_2, v7_1)) {
            v1_1.o("Failed to decrypt encrypted file");
            return;
        }

        Intent v7_2 = new Intent(((Context)v1_1), PdfViewerActivity.class);
        v7_2.putExtra("pdfFilePath", v2.getAbsolutePath());
        ((Context)v1_1).startActivity(v7_2);
```

## Solution
언뜻 봐서는 서버로부터 `/flag`를 얻어올 방법이 없어보인다.
먼저, 수동으로 요청을 보내기 위하여 요청 헤더 값들의 난독화를 해제하였다(`java.lang.String`을 후킹해도 동일한 동작이 가능하다.):
```py
#! /usr/bin/python3

import base64

class Decrypt:
    def __init__(self):
        self.a = []
        self.b = 0
        self.c = 0

    def createKey(self, arg7: list):
        v4 = []
        v0 = 0x100
        self.a = [0]*v0
        v1 = [0]*v0
        v2 = 0
        v3 = 0
        while True:
            v4 = self.a
            if(v3 >= v0):
                break

            v4[v3] = v3
            v1[v3] = int(arg7[v3 % len(arg7)])
            v3 += 1

        v7 = 0
        while v2 < v0:
            v3 = v4[v2]
            v7 = (v7 + v3 + v1[v2]) % v0
            v5 = v4[v7]
            v4[v7] = v3
            v4[v2] = v5
            v2 += 1

    def decryptString(self, arg9: str) -> str:
        idx = 0
        v9 = base64.b64decode(arg9)
        buf = [0]*len(v9)
        v2 = len(v9)
        while idx < v2:
            v3 = (self.b + 1) % 0x100
            self.b = v3
            v4 = self.c
            v5 = self.a
            v6 = v5[v3]
            v4 = (v4 + v6) % 0x100
            self.c = v4
            v7 = v5[v4]
            v5[v4] = v6
            v5[v3] = v7
            buf[idx] = (v5[(v7 + v5[v4]) % 0x100] ^ v9[idx]) & 0xFF
            idx += 1

        return "".join(chr(i) for i in buf)

if __name__ == "__main__":
    dec = Decrypt()

    v9 = [0]*16
    v9[0] = 93
    v9[1] = 25
    v9[2] = 0x81
    v9[3] = 92
    v9[4] = 0xA2
    v9[5] = 0xC3
    v9[6] = 0xF3
    v9[7] = 0x92
    v9[8] = 18
    v9[9] = 33
    v9[10] = 0x9F
    v9[11] = 0x86
    v9[12] = 104
    v9[13] = 94
    v9[14] = 0xFC
    v9[15] = 0xA8
    dec.createKey(v9)

    book_path = "Lz+2zaay1x0XGb3FZ1e8uagOtyImlUfZ0/SxYKce5w=="
    res = dec.decryptString(book_path)
    print(res)

    dec = Decrypt()
    v7_1 = [0]*16
    v7_1[0] = 0xF2
    v7_1[1] = 90
    v7_1[2] = 0xB6
    v7_1[3] = 0x7E
    v7_1[4] = 98
    v7_1[5] = 130
    v7_1[6] = 73
    v7_1[7] = 0x9E
    v7_1[8] = 0xB3
    v7_1[9] = 0xE4
    v7_1[10] = 0xFC
    v7_1[11] = 0x77
    v7_1[12] = 74
    v7_1[13] = 45
    v7_1[14] = 0xA9
    v7_1[15] = 0x7F
    dec.createKey(v7_1)

    user_agent = "0+J3c+9ea5SMfAUvB/rn2AU="
    res = dec.decryptString(user_agent)
    print(res)

    dec = Decrypt()
    v7_1[0] = 0xA1
    v7_1[1] = 0xEF
    v7_1[2] = 0xD7
    v7_1[3] = 17
    v7_1[4] = 0xE3
    v7_1[5] = 0xD7
    v7_1[6] = 0xB7
    v7_1[7] = 0x81
    v7_1[8] = 55
    v7_1[9] = 0x7B
    v7_1[10] = 66
    v7_1[11] = 109
    v7_1[12] = 0x93
    v7_1[13] = 0xFD
    v7_1[14] = 60
    v7_1[15] = 1
    dec.createKey(v7_1)

    authorization = "6orCfU3OtzGoVnwwufNefZChhkXO4/sVOcBvwmTnuyQA6TjDOE1xANwBoNl63DlMnMSj9/8LES0FCCBh8mBimuqdfA=="

    res = dec.decryptString(authorization)
    print(res)

    dec = Decrypt()
    v8 = [0]*16
    v8[0] = 0xF9
    v8[1] = 34
    v8[2] = 0x93
    v8[3] = 28
    v8[4] = 0xED
    v8[5] = 0x20
    v8[6] = 7
    v8[7] = 0xA0
    v8[8] = 25
    v8[9] = 0xA6
    v8[10] = 82
    v8[11] = 0xA5
    v8[12] = 0x77
    v8[13] = 0xAD
    v8[14] = 0x98
    v8[15] = 0x95
    dec.createKey(v8)

    req_book_path = "/qrcqVJKx/BFGBX+HNlhLpUtzrnE3dza1DdeAWrGlD2IPXlJUHHWnN9u"
    res = dec.decryptString(req_book_path)
    print(res)

    dec = Decrypt()
    v8 = [130, 130, 0x99, 10, 107, 150, 0xB0, 0xF3, 0xAF, 0xA7, 21, 0x7C, 33, 0x84, 0xDD, 0xE3]
    dec.createKey(v8)

    download_path = "iiybW1aCSfRbbEn1Heogr/+6/3MsyBxEuvSJjhQdQoL+uh0="
    res = dec.decryptString(download_path)
    print(res)
```

결과는 다음과 같다:
```
/rhBZeQ89tAiYPD41yqoKQN6o/books # 책 리스트 요청
Dr3amDrmUs3rAg3nt # User Agent
Bearer c2VjcmV0X2F1dGhvcml6YXRpb25faGVhZGVyX2Zyb21fZHJlYW1kcm1fYXBw # Authorization
/vXxUDAXOnDqtlt13Vfgods6n/request_book?id= # 특정 책 요청
/CMPpMyH3jV0jzOFKI4oNLS9t/download/ # 특정 책 다운로드
```

각각의 기능을 써보면 `books` 기능을 통해 책의 기본적인 정보를 얻어오고, `request_book` 기능을 통해 복호화를 해제하기 위한 정보와 다운로드 경로를 얻어오며, 마지막으로 책을 다운로드한다는 것을 알 수 있다.

특정 책을 요청할 때, 아래와 같이 요청을 만들게 된다:
```
/vXxUDAXOnDqtlt13Vfgods6n/request_book?id=
```
조작할 부분이 해당 부분밖에 존재하지 않았다고 생각했기 때문에 `SQL Inection`을 시도하였다.
```
/vXxUDAXOnDqtlt13Vfgods6n/request_book?id=1 limit 0,1 # Success
/vXxUDAXOnDqtlt13Vfgods6n/request_book?id=1 limit 1,1 # Fail
```
위 테스트를 통해 `SQL Injection`이 가능하다고 결론을 내릴 수 있다. 반환되는 정보가 `fileName` 이라고 추측하여 아래와 같은 구문을 만들었다:
```
/vXxUDAXOnDqtlt13Vfgods6n/request_book?id=9 UNION ALL SELECT \'/flag\'
```
이를 통해 암호화된 `/flag`와 `key`를 얻을 수 있다.
수동으로 JNI decrypt 함수를 호출하여 바로 복호화된 `/flag`를 얻고 싶었지만 동작하지 않았기 때문에 JNI를 분석하기로 했다.

JNI를 분석하여 복호화 루틴을 분석하기만 하면 되기 때문에 간단할 것이라 생각했지만, 패킹이 걸려있는 듯 보였고 상황 상(군대) 에뮬레이터를 이용한 동적 디버깅만이 가능했다.
하지만 ARM JNI만이 정상적으로 동작했고, x86 64 JNI는 동작하지 않았기 때문에 루팅된 안드로이드 폰이 존재하지 않는 이상 메모리에 올라간 언패킹된 JNI를 정적으로 분석하는 것만이 가능했다.

또한 안티 디버깅이 존재하는데, 이는 후킹으로 간단히 우회할 수 있다:
```py
import frida
import sys

DEVICE = "127.0.0.1:5575"
PACKAGE = "com.theori.dreamdrm"

def on_message(message, data):
    print(f"{message} -> {data}")

js = '''
Java.perform(function(){
    var antiClass = Java.use("y.e");
    antiClass.c.implementation = function() {
        console.log("Hooking y.antiClass.detetAnti: ");
        console.log("Done.")

        return;
    }
});
'''
try:
    dev = frida.get_device(DEVICE)
    # dev = frida.get_usb_device()
    pid = dev.spawn([PACKAGE])
    print(f"App is Starting.. {pid}")
    process = dev.attach(pid)
    dev.resume(pid)
    
    script = process.create_script(js)
    script.on('message', on_message)
    print("Running..")
    script.load()
    input()

except Exception as e:
    print(e)
```

동적으로 애플리케이션에 붙어 언패킹된 decrypt 함수를 확인할 수 있다:
![image.png](https://dreamhack-media.s3.amazonaws.com/attachments/30bdd3dd3c08d5174eb530a93f2499a03a974a0d25d8ca0f4431c8a473a0afc0.png)

편한 분석을 위해 구조체 구현을 얻어왔다:
https://gist.github.com/Jinmo/048776db75067dcd6c57f1154e65b868

복호화가 시작되는 부분이다:
```cpp
  key_decoded = base64_decode(env, key);
  if ( ((unsigned int (__fastcall *)(JNIEnv_ *, __int64))env->functions->GetArrayLength)(env, key_decoded) == 36 )
  {
    v13 = 0LL;
    v12 = 0;
    v11 = 0LL;
    v10 = 0LL;
    ((void (__fastcall *)(JNIEnv_ *, __int64, _QWORD, __int64, __int128 *))env->functions->GetByteArrayRegion)(
      env,
      key_decoded,
      0LL,
      16LL,
      &v13);
    ((void (__fastcall *)(JNIEnv_ *, __int64, __int64, __int64, __int64 *))env->functions->GetByteArrayRegion)(
      env,
      key_decoded,
      16LL,
      12LL,
      &v11);
    ((void (__fastcall *)(JNIEnv_ *, __int64, __int64, __int64, __int64 *))env->functions->GetByteArrayRegion)(
      env,
      key_decoded,
      28LL,
      8LL,
      &v10);
```
키를 base64 디코딩 후 16byte, 12byte, 8byte씩 짜른다.

그 후 복잡한 연산을 통해 키 스케줄링 후 라운드 키를 만들어 복호화를 진행한다.
동적으로 테이블을 만들어 연산하기 때문에 테이블을 통해 알고리즘을 특정하기는 어려웠다.
하지만 AES-NI가 사용되었기 때문에 AES 기반이라는 것은 확실하였다. 내부 루틴을 직접 분석하여 알고리즘을 특정하거나, custom AES임을 확인할 수 없어 다양한 알고리즘을 통해 복호화를 시도하였다.
16byte, 12byte, 8byte의 세 값을 사용하는 알고리즘은 AES-GCM이었기 때문에 이를 시도해보았지만 실패하였다.
crypto++, openssl, tiny-aes 등의 implementation도 참고하였지만 해당 복호화 동작과 비슷한 동작은 찾을 수 없었다.