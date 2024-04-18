/* util.c
 */
#include "../hdr/general.h"

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    dish.food_type = 0xff;
    dish.food_ptr = malloc(FOOD_SIZE);
}

int GetNum() {
    char buf[11];

    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf) - 1);
    return atoi(buf);
}

void ClearBuffer() {
    char c;

    while ((c = getchar()) != EOF && c != '\n');
}
