/* general.c
 */
#include "../hdr/general.h"

struct dish_t dish;

const struct food_menu_t food_menus[7] = {
    {
        .name = SOONDAE_GUKBAP,
        .food_type = FOOD_TYPE_RICE,
        .price = 9000,
        .review_len = 96,
        .cooking_time = 3133700
    },
    {
        .name = BUTADON,
        .food_type = FOOD_TYPE_RICE,
        .price = 9000,
        .review_len = 128,
        .cooking_time = 6221200
    },
    {
        .name = DONKATSU,
        .food_type = FOOD_TYPE_RICE,
        .price = 10500,
        .review_len = 128,
        .cooking_time = 7331300
    },
    {
        .name = JAJANGMYEON,
        .food_type = FOOD_TYPE_NOODLE,
        .price = 8000,
        .review_len = 80,
        .cooking_time = 1337000
    },
    {
        .name = JJAMPPONG,
        .food_type = FOOD_TYPE_NOODLE,
        .price = 9000,
        .review_len = 80,
        .cooking_time = 1337000
    },
    {
        .name = KALGUKSU,
        .food_type = FOOD_TYPE_NOODLE,
        .price = 9000,
        .review_len = 90,
        .cooking_time = 3133700
    },
    {
        .name = RAMEN,
        .food_type = FOOD_TYPE_NOODLE,
        .price = 9000,
        .review_len = 77,
        .cooking_time = 2022600
    }
};
