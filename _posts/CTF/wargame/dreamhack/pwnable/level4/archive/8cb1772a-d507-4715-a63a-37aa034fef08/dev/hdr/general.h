/* general.h
 */
#ifndef _GENERAL_H_
#define _GENERAL_H_

#include <pthread.h>
#include <stddef.h> // offsetof tbd
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FOOD_TYPE_RICE      0
#define FOOD_TYPE_NOODLE    1
#define FOOD_TYPE_INVALID   0xff

#define FOOD_SIZE 0x40

#define SOONDAE_GUKBAP  "Soondae-gukbap"
#define BUTADON         "Butadon"
#define DONKATSU        "Donkatsu-set"
#define JAJANGMYEON     "Jajangmyun"
#define JJAMPPONG       "Jjamppong"
#define KALGUKSU        "Kalguksu"
#define RAMEN           "Ramen"

#define ID_SOONDAE_GUKBAP   0
#define ID_BUTADON          1
#define ID_DONKATSU         2
#define ID_JAJANGMYEON      3
#define ID_JJAMPPONG        4
#define ID_KALGUKSU         5
#define ID_RAMEN            6

struct dish_t {
    uint8_t food_type;
    void *food_ptr;
};

struct food_menu_t {
    char name[16];
    uint8_t food_type;
    unsigned int price;
    size_t review_len;
    unsigned int cooking_time;
};

struct rice_t {
    char name[16];
    size_t review_len;
    unsigned int price;
    unsigned int cooking_time;
};

struct noodle_t {
    char name[12];
    size_t review_len;
    unsigned int price;
    unsigned int cooking_time;
};

extern struct dish_t dish;
extern const struct food_menu_t food_menus[7];

#endif
