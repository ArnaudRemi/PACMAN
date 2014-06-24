/*
    Copyright (C) 2004 Ingmar Baumgart <ingmar@ibgt.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _LIST_H
#define _LIST_H

#include <unistd.h>

typedef struct list_t {
	struct list_t *prev;
	struct list_t *next;
} list_t;

typedef int (*cmp_func_t)(list_t *a, list_t *b);

#define foreach_listitem(pos, head) \
	for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

void add_item_behind_pos(list_t *pos, list_t *item);
void add_item(list_t *head, list_t *item);
void add_item_sorted(list_t *head, list_t *item, cmp_func_t cmp);
void unlink_item(list_t *item);
void destroy_list(list_t *head);

#endif /*_LIST_H */

