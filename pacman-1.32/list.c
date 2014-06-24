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

#include <stdlib.h>

#include "list.h"

void add_item_behind_pos(list_t *pos, list_t *item)
{
	item->prev=pos;
	item->next=pos->next;
	
	(pos->next)->prev=item;
	pos->next=item;

}

void add_item(list_t *head, list_t *item)
{
	add_item_behind_pos(head, item);
}

void add_item_sorted(list_t *head, list_t *item, cmp_func_t cmp )
{
	list_t *pos;

	foreach_listitem(pos, head) {
		if(cmp(pos, item)) break;
	}
	
	add_item_behind_pos(pos->prev, item);
}

void unlink_item(list_t *item)
{
	(item->prev)->next=item->next;
	(item->next)->prev=item->prev;
	
	item->prev = item->next = NULL;
}

void destroy_list(list_t *head)
{
	list_t *pos, *tmp = NULL;
	
	foreach_listitem(pos, head) {
		free(tmp);
		tmp = pos;
	}
	free(tmp);
}
