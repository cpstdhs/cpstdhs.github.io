# mobile CTF TIPS
> 기본적인 mobile tools 사용법 정리

## Category
- [mobile CTF TIPS](#mobile-ctf-tips)
  - [Category](#category)
  - [apktool](#apktool)
  - [signing](#signing)
  - [adb](#adb)
    - [Package Manager:](#package-manager)
    - [Activity Manager:](#activity-manager)
  - [remote debugging via IDA](#remote-debugging-via-ida)

## apktool
apk reversing에 관한 대부분의 작업을 지원해주는 툴이다.
- decompile:
```sh
apktool d test.apk -o test
```
- compile:
```sh
apktool b test -o test.apk
```
## signing
jdk에 `keytool.exe`, `jarsigner.exe`가 존재하는데, keytool로 key를 생성하고, jarsigner로 apk에 서명을 진행하면 된다.
- generate public key:
```sh
keytool -genkey -v -keystore <임의파일명.keystore> -alias <임의별칭> -keyalg RSA -keysize 2048
```
- sign to apk
```
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore <생성한 keystore파일> <리패키징한 앱> <지정한 별칭>
```
## adb
기기를 쉽게 디버깅할 수 있도록 다리를 놓아주는 기능을 하는 툴이다.

- connect:
```
adb connect 127.0.0.1:5555
```
- shell:
```
adb -s 127.0.0.1:5555 shell
```
- install:
```
adb -s 127.0.0.1:5555 install -r patch.apk
```

- more:
```sh
adb devices	연결된 Android 장치 또는 에뮬레이터를 나열합니다. 장치가 제대로 연결되고 ADB에서 인식하는지 확인하는 데 자주 사용됩니다.
adb shell	연결된 Android 장치 또는 에뮬레이터에서 대화형 셸을 엽니다. 터미널을 사용하는 것과 유사하게 장치에서 직접 명령을 실행할 수 있습니다.
adb install <path_to_apk>	연결된 장치 또는 에뮬레이터에 Android 애플리케이션(APK 파일)을 설치합니다. 설치하려는 APK 파일의 경로를 제공해야 합니다.
adb uninstall <package_name>	연결된 장치 또는 에뮬레이터에서 설치된 Android 애플리케이션을 제거합니다. 제거할 애플리케이션의 패키지 이름을 지정해야 합니다.
adb push <local_path> <device_path>	컴퓨터에서 연결된 Android 장치의 지정된 위치로 파일 또는 디렉토리를 복사합니다. 푸시하려는 파일/디렉토리의 로컬 경로와 장치의 대상 경로를 제공해야 합니다.
adb pull <device_path> <local_path>	연결된 Android 장치에서 컴퓨터로 파일 또는 디렉토리를 복사합니다. 장치의 파일/디렉토리 경로와 컴퓨터의 대상 경로를 제공해야 합니다.
adb logcat	Android 장치 또는 에뮬레이터의 로그 메시지를 표시합니다. 애플리케이션의 런타임 동작 및 오류 메시지를 디버깅하고 모니터링하는 데 유용합니다.
adb reboot	연결된 Android 장치 또는 에뮬레이터를 재부팅합니다.
adb connect <device_ip_address>[:<port>]	네트워크를 통해 Android 기기 또는 에뮬레이터에 연결하는 데 사용됩니다.
```

### Package Manager:
- more:
```sh
adb shell pm install <path_to_apk>	APK 파일을 설치할 수 있습니다.
adb shell pm uninstall <package_name>	패키지를 제거할 수 있습니다.
adb shell pm list packages	디바이스에 설치된 패키지의 목록을 확인할 수 있습니다.
adb shell pm dump <package_name>	특정 패키지의 자세한 정보를 확인할 수 있습니다.
```

### Activity Manager:
- more: 
```sh
adb shell am start	활동을 시작하거나 전경으로 가져옵니다.
adb shell am force-stop	패키지 이름을 지정하여 애플리케이션을 강제로 중지합니다.
adb shell am broadcast	관심 있는 모든 수신자에게 의도를 브로드캐스트합니다.
adb shell am clear	애플리케이션과 관련된 데이터 및 캐시를 지웁니다.
adb shell am startservice	서비스를 시작합니다.
adb shell am start-foreground-service	포그라운드 서비스를 시작합니다.
adb shell am instrument	지정된 구성 요소에 대한 계측 테스트를 시작합니다.
```

- furthermore:
```
-n <component_name>	대상에 대한 활동, 서비스 또는 수신기의 구성 요소 이름(패키지 이름 + 클래스 이름)을 지정합니다.

adb shell am start -n com.example.myapp/.MainActivity
-a <action>	수행할 작업을 지정합니다. 시작 및 방송과 같은 다양한 하위 명령과 함께 사용할 수 있습니다.

adb shell am start -a android.intent.action.VIEW
-d <data_uri>	관작업에 대한 데이터 URI를 지정합니다. 대상 구성 요소에 데이터를 전달하는 데 사용할 수 있습니다.

adb shell am start -d "http://www.example.com"
-t <mime_type>	작업 데이터의 MIME 유형을 지정합니다. -d 옵션과 함께 사용됩니다.

adb shell am start -d "content://com.example.provider/data" -t "vnd.android.cursor.item/example"
--es <extra_key> <extra_value>	대상 구성 요소에 전달할 추가 문자열 값을 지정합니다. 추가 데이터 또는 매개 변수를 제공하는 데 사용됩니다.

adb shell am broadcast --es "message" "Hello, World!"
-w	포시작된 활동이 완료될 때까지 기다렸다가 돌아갑니다. start 및 instrument 하위 명령과 함께 사용할 수 있습니다.

adb shell am start -n com.example.myapp/.MainActivity -w
-r	install 하위 명령을 사용할 때 기존 응용 프로그램을 대체합니다. 동일한 패키지 이름으로 응용 프로그램을 다시 설치하는 데 사용됩니다.

adb shell am install -r /path/to/app.apk
```

## remote debugging via IDA
```
adb -s 127.0.0.1:5556 forward tcp:23946 tcp:23946
```

```
adb -s 127.0.0.1:5556 push "C:\Program Files\IDA Pro 8.3\dbgsrv\android_x64_server" /data/local/tmp
```
```
IDA - Debugger - Attach - Attach Linux Debugger - 127.0.0.1:23946
```