/* view.c
 */
#include "../hdr/general.h"
#include "../hdr/view.h"

void ViewFood() {
    switch (dish.food_type) {
    case FOOD_TYPE_RICE:
        ViewRiceMenu();
        break;
    case FOOD_TYPE_NOODLE:
        ViewNoodleMenu();
        break;
    }
}

void ViewRiceMenu() {
    struct rice_t *rice_menu;

    rice_menu = dish.food_ptr;

    puts(" [ Your dish (rice menu) ]");
    printf("Food name: %s\n", rice_menu->name);
    printf("Food price: %u\n", rice_menu->price);
    printf("Cooking time: %u\n", rice_menu->cooking_time);
}

void ViewNoodleMenu() {
    struct noodle_t *noodle_menu;

    noodle_menu = dish.food_ptr;

    puts(" [ Your dish (noodle menu) ]");
    printf("Food name: %s\n", noodle_menu->name);
    printf("Food price: %u\n", noodle_menu->price);
    printf("Cooking time: %u\n", noodle_menu->cooking_time);
}
