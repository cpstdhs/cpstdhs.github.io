FROM ubuntu:20.04

# Setup environ
ENV user dlmalloc
ENV prob_port 13100

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirror.kakao.com/g" /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y socat \
 && rm -rf /var/lib/apt/lists/*

# Additional configuration
RUN adduser --disabled-password --gecos "" $user
ADD ./run.sh /home/$user/run.sh
ADD ./vuln /home/$user/vuln
ADD ./flag /home/$user/flag
ADD ./libdlmalloc.so /home/$user/libdlmalloc.so

RUN chown root:$user /home/$user/vuln
RUN chown root:$user /home/$user/flag

RUN chmod 440 /home/$user/flag
RUN chmod 755 /home/$user/run.sh
RUN chmod 755 /home/$user/vuln

WORKDIR /home/$user
CMD socat -T 60 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/run.sh,stderr,su=$user
EXPOSE $prob_port

