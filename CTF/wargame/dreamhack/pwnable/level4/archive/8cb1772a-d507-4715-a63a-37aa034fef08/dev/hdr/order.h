/* order.h
 */
#ifndef _ORDER_H_
#define _ORDER_H_

#include "../hdr/general.h"

void OrderFood();
void Cook(void *data);
void CookRiceMenu(const struct food_menu_t *food_menu);
void CookNoodleMenu(const struct food_menu_t *food_menu);

#endif
