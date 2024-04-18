/* chatbot_client.c
 * gcc -Wall -no-pie chatbot_client.c -o chatbot_client
*/
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MSG_SIZE 256

#define PrintError(s) {puts(s); exit(1);}

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

int main(int argc, char *argv[]) {
    char msg[MSG_SIZE];
    int sockfd;
    size_t msglen;
    struct sockaddr_in srv_addr;

    Init();

    if (argc != 3) {
        printf("usage) %s [IP] [PORT]\n", argv[0]);
        exit(1);
    }

    memset(&srv_addr, 0x00, sizeof(srv_addr));

    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
        PrintError("socket() error.");

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    srv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1)
        PrintError("connect() error.");

    while (1) {
        memset(msg, 0x00, sizeof(msg));
        printf("client: ");
        fgets(msg, sizeof(msg), stdin);

        msglen = strlen(msg);
        if (msg[msglen - 1] == '\n')
            msg[msglen - 1] = 0x00;

        if (!strcmp(msg, "/quit"))
            break;

        if (write(sockfd, msg, sizeof(msg)) == -1)
            PrintError("write() error.");

        memset(msg, 0x00, sizeof(msg));
        if (read(sockfd, msg, sizeof(msg)) == -1)
            PrintError("read() error.");

        printf("server: %s\n", msg);
    }

    close(sockfd);

    return 0;
}
