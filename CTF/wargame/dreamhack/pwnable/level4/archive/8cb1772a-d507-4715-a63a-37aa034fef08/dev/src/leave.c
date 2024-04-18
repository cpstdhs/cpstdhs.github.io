/* leave.c
 */
#include "../hdr/general.h"
#include "../hdr/leave.h"

void LeaveReview() {
    if (dish.food_type == FOOD_TYPE_INVALID)
        return;

    switch (dish.food_type) {
    case FOOD_TYPE_RICE:
        LeaveReviewForRiceMenu();
        break;
    case FOOD_TYPE_NOODLE:
        LeaveReviewForNoodleMenu();
        break;
    }
}

void LeaveReviewForRiceMenu() {
    char review[MAX_REVIEW_SIZE];
    struct rice_t *rice_menu;

    rice_menu = dish.food_ptr;
    printf("How about our rice food '%s'? ", rice_menu->name);
    fgets(review, rice_menu->review_len, stdin);
    puts("Thank you for writing review. It will help improve our restaurant.");
}

void LeaveReviewForNoodleMenu() {
    char review[MAX_REVIEW_SIZE];
    struct noodle_t *noodle_menu;

    noodle_menu = dish.food_ptr;
    printf("How about our noodle food '%s'? ", noodle_menu->name);
    fgets(review, noodle_menu->review_len, stdin);
    puts("Thank you for writing review. It will help improve our restaurant.");
}
