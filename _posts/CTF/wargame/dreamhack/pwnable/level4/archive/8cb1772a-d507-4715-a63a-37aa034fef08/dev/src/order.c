/* order.c
 */
#include "../hdr/general.h"
#include "../hdr/order.h"
#include "../hdr/util.h"

void OrderFood() {
    char food_name[32];
    int i;
    pthread_t p;

    memset(food_name, 0x00, sizeof(food_name));
    printf("What food do you want? ");
    scanf("%31s", food_name);
    ClearBuffer();

    for (i = 0; i < sizeof(food_menus) / sizeof(food_menus[0]); i++) {
        if (!strcmp(food_name, food_menus[i].name)) {
            pthread_create(&p, NULL, (void *)Cook, (void *)&i);
            usleep(31337);
            return;
        }
    }

    puts("There is no such food :(");
}

void Cook(void *data) {
    const struct food_menu_t *food_menu;
    uint8_t food_menu_id;

    food_menu_id = *(uint8_t *)data;
    food_menu = &food_menus[food_menu_id];

    switch (food_menu->food_type) {
    case FOOD_TYPE_RICE:
        CookRiceMenu(food_menu);
        break;
    case FOOD_TYPE_NOODLE:
        CookNoodleMenu(food_menu);
        break;
    }
}

void CookRiceMenu(const struct food_menu_t *food_menu) {
    struct rice_t *rice_food;

    printf("\n\nCooking rice food '%s'...\n", food_menu->name);
    usleep(food_menu->cooking_time);
    dish.food_type = food_menu->food_type;
    usleep(31337);
    rice_food = (struct rice_t *)dish.food_ptr;
    memset(rice_food, 0x00, FOOD_SIZE);
    strcpy(rice_food->name, food_menu->name);
    rice_food->price = food_menu->price;
    rice_food->review_len = food_menu->review_len;
    rice_food->cooking_time = food_menu->cooking_time;

    puts("\nYour dish has arrived!");
}

void CookNoodleMenu(const struct food_menu_t *food_menu) {
    struct noodle_t *noodle_food;

    printf("\n\nCooking noodle food '%s'...\n", food_menu->name);
    usleep(food_menu->cooking_time);
    dish.food_type = food_menu->food_type;
    noodle_food = (struct noodle_t *)dish.food_ptr;
    memset(noodle_food, 0x00, FOOD_SIZE);
    strcpy(noodle_food->name, food_menu->name);
    noodle_food->price = food_menu->price;
    noodle_food->review_len = food_menu->review_len;
    noodle_food->cooking_time = food_menu->cooking_time;
    puts("\nYour dish has arrived!");
}
