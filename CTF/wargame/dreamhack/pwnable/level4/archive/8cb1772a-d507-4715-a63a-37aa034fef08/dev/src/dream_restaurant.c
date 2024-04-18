/* dream_restaurant.c
*/
#include "../hdr/general.h"
#include "../hdr/leave.h"
#include "../hdr/order.h"
#include "../hdr/util.h"
#include "../hdr/view.h"

#define MENU_ORDER_FOOD     1
#define MENU_VIEW_FOOD      2
#define MENU_QUIT           3

static void PrintMenu();

int main(void) {
    int menu;

    Init();
    do {
        PrintMenu();
        menu = GetNum();
        switch (menu) {
        case MENU_ORDER_FOOD:
            OrderFood();
            break;
        case MENU_VIEW_FOOD:
            ViewFood();
            break;
        case MENU_QUIT:
            LeaveReview();
            break;
        default:
            puts("wrong menu!");
        }
    } while (menu != MENU_QUIT);
    puts("byebye");
    return 0;
}

void PrintMenu() {
    puts("==============================================");
    puts("*                                            *");
    puts("*              Dream Restaurant              *");
    puts("*                                            *");
    puts("==============================================");
    puts("1. order food");
    puts("2. view food");
    puts("3. quit");
    printf("> ");
}
