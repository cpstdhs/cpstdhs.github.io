# 🐋 docker
> docker 기본적인 사용법 정리

# Category
- [🐋 docker](#-docker)
- [Category](#category)
  - [run container](#run-container)
  - [container list](#container-list)
  - [container stop](#container-stop)
  - [delete container](#delete-container)
  - [image list](#image-list)
  - [download image](#download-image)
  - [delete image](#delete-image)
  - [container log](#container-log)
  - [container exec command](#container-exec-command)
  - [offline .tar image load](#offline-tar-image-load)
  - [Dockerfile](#dockerfile)
  - [docker-compose](#docker-compose)
  - [remote debugging via](#remote-debugging-via)

## run container
```
docker run [OPTIONS] IMAGE[:TAG|@DIGEST] [COMMAND] [ARG...]
```
```
-d: detached mode (백그라운드 모드)
-p: 호스트와 컨테이너의 포트를 연결(포트 포워딩)
-v: 호스트와 컨테이너의 디렉터리를 연결(마운트)
-e: 컨테이너 내에서 사용할 환경변수 설정
-name: 컨테이너 이름 설정
-rm: 프로세스 종료시 컨테이너 자동 제거
-it: 터미널 입력을 위한 옵션
-link: 컨테이너 연결 [컨테이너명:별칭]
```
```
docker run --rm -it ubuntu:16.04 /bin/bash
```

## container list
```
docker ps [OPTIONS]
```
```
-a, -all
```

## container stop
```
docker stop [OPTIONS] CONTAINER [CONTAINER..]
```

## delete container
```
docker rm [OPTIONS] CONTAINER [CONTAINER..]
```

## image list
```
docker images [OPTIONS] [REPOSITORY[:TAG]]
```

## download image
```
docker pull [OPTIONS] NAME[:TAG|@DIGEST]
```

## delete image
```
docker rmi [OPTIONS] IMAGE [IMAGE..]
```

## container log
```
docker logs [OPTIONS] CONTAINER
```
```
-f: 실시간 로그 출력
--tail 10: 뒤 10줄만 출력
```

## container exec command
```
docker exec [OPTIONS] CONTAINER COMMAND [ARG..]
```

## offline .tar image load
```
docker load -i TAR
```

## Dockerfile
이미지를 빌드할 수 있도록 하는 설정 파일
```
docker build -t .
```

## docker-compose
이미지를 쉽게 실행할 수 있게 해주는 설정 파일
```
docker-compose up -d
```

## remote debugging via 
- docker-compose
```
    ports:
      - "22244:22244"
    cap_add:
      - SYS_PTRACE
```
- Dockerfile
```sh
RUN apt-get install -y gdb
RUN apt-get install -y gdbserver
RUN apt-get install -y libc6-dbg
```
- /home/dev/_attach_process.sh
```sh
#!/usr/bin/env bash
ps -ef | grep protoss | grep -v grep | grep -v socat | awk "{print $2}" | { read pid; gdbserver --attach :22244 $pid; }
```
```sh
echo '#!/usr/bin/env bash
ps -ef | grep protoss | grep -v grep | grep -v socat | awk "{print \$2}" | { read pid; gdbserver --attach :22244 $pid; }' > /home/dev/_attach_process.sh
chmod +x /home/dev/_attach_process.sh
```
컨테이너 내부에 위 파일 배치

- run_attach_process.sh
```sh
#!/usr/bin/env bash
docker exec -d protoss /bin/bash /home/dev/_attach_process.sh
```
컨테이너 외부에서 해당 스크립트 실행

```sh
target remote localhost:22244
```
컨테이너 내부에서 fork된 프로세스에 붙어서 디버깅 진행

- example
```py
from pwn import *
from subprocess import check_output

PROTOSS_PORT = 5050
MYSQL_PORT = 3306
DEBUG_PORT = 22244
BINARY_PATH = "./protoss"

s = connect('localhost', PROTOSS_PORT)
e = ELF(BINARY_PATH)

gs = '''
'''

def db():
    check_output('./run_attach_process.sh')
    gdb.attach(target=('localhost', DEBUG_PORT), exe=BINARY_PATH, gdbscript=gs)
    pause()

db()

s.interactive()
```