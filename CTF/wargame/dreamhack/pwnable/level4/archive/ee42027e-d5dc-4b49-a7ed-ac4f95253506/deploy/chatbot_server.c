/* chatbot_server.c
 * gcc -Wall -no-pie chatbot_server.c -o chatbot_server
*/
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MSG_SIZE        256
#define MAX_BOT_MSGS    20
#define BOT_MSG_SIZE    128

#define PrintError(s) {puts(s); exit(1);}

char *PickRandomMessage(char (*bot_msgs)[][BOT_MSG_SIZE]) {
    char *random_msg = 0;
    do {
        random_msg = (*bot_msgs)[rand() % MAX_BOT_MSGS];
    } while (random_msg[0] == 0x00);
    return random_msg;
}

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    srand(time(NULL));
    printf("[*] Server started.");
}

int main(void) {
    char *bot_msg;
    char bot_msgs[MAX_BOT_MSGS][BOT_MSG_SIZE] = {
        "Hi there!",
        "What kind of bot would you like to have?",
        "I wish someone would improve me.",
        "How are you today?",
        "Great!",
        "How's it going?",
        "Do I have a bug?",
        "Oh really?",
        "Do you want some cookies?",
	"choco'-chip? or sprinkle?",
    };
    char msg[MSG_SIZE];
    int clnt_sockfd;
    int optval;
    int srv_sockfd;
    socklen_t clnt_addrlen;
    struct sockaddr_in clnt_addr;
    struct sockaddr_in srv_addr;
    int i;

    Init();
    i = 9;

    memset(&clnt_addr, 0x00, sizeof(clnt_addr));
    memset(&srv_addr, 0x00, sizeof(srv_addr));

    srv_sockfd = socket(PF_INET, SOCK_STREAM, 0);

    if (srv_sockfd == -1)
        PrintError("socket() error.");

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    srv_addr.sin_port = htons(31337);

    if (setsockopt(srv_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
        PrintError("setsockopt() error.");

    if (bind(srv_sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1)
        PrintError("bind() error.");

    if (listen(srv_sockfd, 10000) == -1)
        PrintError("listen() error.");

    clnt_addrlen = sizeof(clnt_addr);
    clnt_sockfd = accept(srv_sockfd, (struct sockaddr *)&clnt_addr, &clnt_addrlen);
    if (clnt_sockfd == -1)
        PrintError("accept() error.");

    puts("A client has connected to the server.");

    while (1) {
        memset(msg, 0x00, sizeof(msg));
        if (read(clnt_sockfd, msg, sizeof(msg)) == -1)
            PrintError("read() error.");
        printf("client: %s\n", msg);

        if (!strcmp(msg, "/quit"))
            break;

        if (!memcmp(msg, "/addmsg ", sizeof("/addmsg"))) {
            memset(bot_msgs[i % MAX_BOT_MSGS], 0x00, BOT_MSG_SIZE);
            strncpy(bot_msgs[i++ % MAX_BOT_MSGS], &msg[8], BOT_MSG_SIZE - 1);

            printf("msg: %s\n", msg);
            strncpy(msg, "Thank you for improving me :)", 30);
            if (write(clnt_sockfd, msg, sizeof(msg)) == -1)
                PrintError("write() error.");
            printf("server: %s\n", msg);

            continue;
        }

        memset(msg, 0x00, sizeof(msg));
        bot_msg = PickRandomMessage(&bot_msgs);
        snprintf(msg, sizeof(msg), bot_msg, 0);
        if (write(clnt_sockfd, msg, sizeof(msg)) == -1)
            PrintError("write() error.");
        printf("server: %s\n", msg);
    }

    close(clnt_sockfd);
    close(srv_sockfd);
    printf("[*] Server terminated at ");
    system("date");

    return 0;
}
