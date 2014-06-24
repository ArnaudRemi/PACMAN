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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"
#include "table.h"
#include "pacman.h"

htable_t htable;

local_ls_t loc_ls_tab;

int is_bigger(list_t *a, list_t *b)
{
	return( ((neighbors_t*)a)->addr > ((neighbors_t*)b)->addr );
}

char* print_ip(u_int32_t addr)
{
	static char buf[17];
	
	sprintf(buf, "%u.%u.%u.%u", addr>>24, (addr>>16)&0xff, (addr>>8)&0xff,
		addr&0xff);

	return buf;
}

u_int32_t hash_ip_addr(u_int32_t ip)
{
	return(ip & HASHMASK);
}


void init_htable()
{
	int i;
	
	for(i = 0; i < HTABLE_SIZE; i++) {
		init_list(htable.lhead[i]);
	}
}

void init_loc_ls_tab(u_int32_t addr)
{
	loc_ls_tab.addr = addr;
	loc_ls_tab.seqn[LS_TYPE1] = 0;
	loc_ls_tab.seqn[LS_TYPE2] = 0;
	init_list(loc_ls_tab.l_neigh);
	update_addr_list(addr);
}	

void print_linkstate_entry(ls_entry_t *e)
{
	list_t *pos;
	
        PRINTF("---------------------------------------\n");
        PRINTF("orig_addr: %s    ", print_ip(e->orig_addr));
        PRINTF("type: %i  ", e->type);
        PRINTF("seqn: %u\n", e->seqn);
        PRINTF("neighbors: ");
        foreach_listitem(pos, &e->neighbors) {
                PRINTF("%s%s ", print_ip( ((neighbors_t*)pos)->addr),
		       (((neighbors_t*)pos)->linkcode == LC_MPR)?"(MPR)":"");
        }
        PRINTF("\n---------------------------------------\n\n");

}

void dump_linkstate_table()
{
	u_int32_t index;
	list_t *pos;

	PRINTF("LS table:\n");

	for(index = 0; index < HTABLE_SIZE; index++) {
		PRINTF("#%i:\n", index);	
		foreach_listitem(pos, &(htable.lhead[index]))
			if(IS_LS_ENTRY(pos))
				print_linkstate_entry((ls_entry_t*)pos);
	}
	PRINTF("\n");
}

void print_conflict_entry(conf_entry_t *c)
{
	PRINTF("%s: ", print_ip(c->orig_addr));
	PRINTF("p=%.3f ", c->conf_p);
	PRINTF("acn_msg_ts[0]: %lu.%lu ", c->acn_msg_ts[0].tv_sec,
		c->acn_msg_ts[0].tv_usec);
	PRINTF("acn_msg_ts[1]: %lu.%lu\n", c->acn_msg_ts[1].tv_sec,
		c->acn_msg_ts[1].tv_usec);
}

void dump_conflict_table()
{
	u_int32_t index;
	list_t *pos;

	PRINTF("conflict table:\n");

	for(index = 0; index < HTABLE_SIZE; index++) {
		PRINTF("#%i:\n", index);	
		foreach_listitem(pos, &(htable.lhead[index]))
			if(IS_CONF_ENTRY(pos))
				print_conflict_entry((conf_entry_t*)pos);
	}
	PRINTF("\n");
}

void dump_loc_ls_tab()
{
	list_t *pos;
	loc_neigh_t *ln;

	PRINTF("loc_ls_tab dump:\n");

        PRINTF("myaddr: %s  ", print_ip(loc_ls_tab.addr));
        PRINTF("seqn1: %u  seqn2: %u\n",loc_ls_tab.seqn[0],loc_ls_tab.seqn[1]);

        PRINTF("my neighbors:\t");
        foreach_listitem(pos, &(loc_ls_tab.l_neigh)) {
                        ln = (loc_neigh_t*)pos;
                        PRINTF("\t\t%s ", print_ip(ln->addr));
			if(ln->linkcode == LC_MPR)
				PRINTF("MPR ");
                        PRINTF("ts: %lu\n", ln->ts.tv_sec);
        }
        PRINTF("\n");
}

/* returns min(|LS1 - LS2|, max_diff) */
int ls_differ(ls_entry_t *e1, ls_entry_t *e2, int max_diff)
{
	int hits = 0;
	int differ;
	int cnt2 = e2->n_cnt;
	list_t *pos1, *pos2;

	if (abs(e1->n_cnt - e2->n_cnt) >= max_diff) return max_diff;

	pos2 = e2->neighbors.next;

	if(e2->n_cnt) foreach_listitem(pos1, &e1->neighbors) {
		while (is_bigger(pos1, pos2)) {
			pos2 = pos2->next;
			if (--cnt2 == 0) goto end_ls_differ;
		}
		if (((neighbors_t*)pos1)->addr == ((neighbors_t*)pos2)->addr) {
			hits++;
			pos2 = pos2->next;
			if (--cnt2 == 0) goto end_ls_differ;
		}
	}

end_ls_differ:
	differ = e1->n_cnt + e2->n_cnt - 2*hits;
	DEBUG(DEBUG_PDAD, "ls_differ(): e1->n_cnt:%i, e2->n_cnt:%i, hits:%i, "
	      "differ:%i\n", e1->n_cnt, e2->n_cnt, hits, differ);

	if(!differ) return 0;
	else {
		if (e1->n_cnt < 2) return -1;
		if (e2->n_cnt < 2) return -1;
		return (differ);
	}
}

u_int32_t count_htable_entries(int type)
{
	u_int32_t index;
	list_t *pos;
	u_int32_t cnt = 0;

	for(index = 0; index < HTABLE_SIZE; index++) {
		foreach_listitem(pos, &(htable.lhead[index]))
			if(((generic_entry_t*)pos)->type == type)
				cnt++;
	}
	return cnt;
}


/* create a new ls_entry with given orig_addr and seqn */
ls_entry_t* new_ls_entry(u_int32_t addr, u_int32_t seqn, int type)
{
	ls_entry_t *e;

	if ((e = (ls_entry_t*)malloc(sizeof(ls_entry_t))) == NULL) {
		perror("new_ls_entry()");
		exit(1);
	}

	init_list(e->neighbors);

	e->orig_addr = addr;
	e->seqn = seqn;
	e->type = type;
	e->n_cnt = 0;
	gettimeofday(&e->ts, NULL);

	return e;
}

/* create a new conf_entry */
conf_entry_t* new_conf_entry(u_int32_t addr)
{
	u_int32_t index;
	conf_entry_t *c;

	if ((c = (conf_entry_t*)malloc(sizeof(conf_entry_t))) == NULL) {
		perror("new_conf_entry()");
		exit(1);
	}

	c->orig_addr = addr;
	c->type = CONF_TYPE;
	gettimeofday(&c->ts, NULL);
	c->acn_msg_ts[0].tv_sec = 0;
	c->acn_msg_ts[0].tv_usec = 0;
	c->acn_msg_ts[1].tv_sec = 0;
	c->acn_msg_ts[1].tv_usec = 0;
	c->conf_p = 0;

	index = hash_ip_addr(c->orig_addr);
	add_item( &(htable.lhead[index]), (list_t*)c );

	return c;
}

void update_addr_list(u_int32_t addr)
{
	generic_entry_t *g;

	if (addr == 0) return;

	if ((g = (generic_entry_t*)malloc(sizeof(generic_entry_t))) == NULL) {
		perror("update_addr_list()");
		exit(1);
	}

	g->orig_addr = addr;
	g->type = ADDR_LIST_TYPE;
	gettimeofday(&g->ts, NULL);

	insert_htable_entry(g);
}

/* search address in ls_entry_t */
neighbors_t* search_ls_neighbor(ls_entry_t *e, u_int32_t addr)
{
	list_t *pos;

	foreach_listitem(pos, &e->neighbors)
		if ( ((neighbors_t*)pos)->addr == addr )
			return (neighbors_t*)pos;
	return NULL;
}

/* search address in loc_ls_tab */
loc_neigh_t* search_loc_ls_tab( u_int32_t addr)
{
	list_t *pos;

	foreach_listitem(pos, &loc_ls_tab.l_neigh)
		if ( ((loc_neigh_t*)pos)->addr == addr )
			return (loc_neigh_t*)pos;
	return NULL;
}

/* add address to ls_entry_t */
void update_ls_neighbor(ls_entry_t *e, u_int32_t addr, u_int8_t linkcode)
{
	neighbors_t *n;

	if ((n = (neighbors_t*)malloc(sizeof(neighbors_t))) == NULL) {
		perror("update_ls_neighbor()");
		exit(1);
	}
		
	n->addr = addr;
	n->linkcode = linkcode;
	add_item_sorted(&(e->neighbors), &(n->l), &is_bigger);
	e->n_cnt++;
}

void update_linkcode(loc_neigh_t *old, loc_neigh_t *new)
{
	if((new->linkcode != LC_MPR) &&
	   (old->linkcode == LC_MPR) &&
	   ((new->lc_ts.tv_sec - old->lc_ts.tv_sec) <= t_d+MPR_TRESH)) {
		new->lc_ts = old->lc_ts;
		new->linkcode = LC_MPR;
	}
}


/* add address to list of local neighbors */
void update_loc_neighbor(u_int32_t addr, u_int8_t linkcode)
{
	loc_neigh_t *ln;
	list_t *pos;

	DEBUG(DEBUG_TABLE, "update_neighbor(%s)\n", print_ip(addr));

	if ((ln=(loc_neigh_t*)malloc(sizeof(loc_neigh_t)))==NULL) {
			perror("update_neighbor()");
			exit(1);
	}

	ln->addr = addr;
	ln->linkcode = linkcode;
	gettimeofday(&ln->lc_ts, NULL);
	gettimeofday(&ln->ts, NULL);

	/* if entry already exists, replace with new one */
	if ((pos = (list_t*)search_loc_ls_tab(addr)) != NULL) {
		update_linkcode((loc_neigh_t*)pos, ln);
		add_item_behind_pos(pos, (list_t*)ln);
		unlink_item(pos);
		free(pos);
	} else add_item(&loc_ls_tab.l_neigh, (list_t*)ln);
}

void* find_htable_entry(u_int32_t addr, int type)
{
	u_int32_t index;
	list_t *pos;

	index = hash_ip_addr(addr);
	
	foreach_listitem(pos, &(htable.lhead[index])) {
		if (((ls_entry_t*)pos)->orig_addr == addr) {
			/* return only entries matching type */
			if (((ls_entry_t*)pos)->type != type)
				continue;
			return (void*)pos;
		}
	}
	
	return NULL;
}

ls_entry_t* find_ls_entry(u_int32_t addr, int type)
{
	return (ls_entry_t*)find_htable_entry(addr, type);
}

conf_entry_t* find_conf_entry(u_int32_t addr)
{
	return (conf_entry_t*)find_htable_entry(addr, CONF_TYPE);
}

void delete_htable_entry(generic_entry_t *g)
{
	unlink_item((list_t*)g);
	if (IS_LS_ENTRY(g)) destroy_list(&((ls_entry_t*)g)->neighbors);
	free((list_t*)g);
}

void insert_ls_entry(ls_entry_t *e)
{

	insert_htable_entry((generic_entry_t*)e);
}

void insert_htable_entry(generic_entry_t *g)
{
	u_int32_t index;
	list_t *pos;
	
	/* if entry already exists, replace with new one */
	if ((pos=(list_t*)find_htable_entry(g->orig_addr, g->type)) != NULL) {
		add_item_behind_pos(pos, (list_t*)g);
		delete_htable_entry((generic_entry_t*)pos);
	} else {
		index = hash_ip_addr(g->orig_addr);
		add_item( &(htable.lhead[index]), (list_t*)g );
	}
}

void table_cleanup_timer()
{
	struct timeval now;
	list_t *pos, *tmp = NULL;
	int index;

	gettimeofday(&now, NULL);

	DEBUG(DEBUG_TABLE, "table_cleanup_timer (now:%li)\n", now.tv_sec);
	for(index = 0; index < HTABLE_SIZE; index++) {
		foreach_listitem(pos, &(htable.lhead[index])) {
			if (tmp) {
				delete_htable_entry((generic_entry_t*)tmp);
				tmp = NULL;
			}

			if (now.tv_sec - ((ls_entry_t*)pos)->ts.tv_sec
			    > HTABLE_TIMEOUT) {
				DEBUG(DEBUG_TABLE,"entry %s type %i removed\n",
				      print_ip(((generic_entry_t*)pos)->orig_addr), ((generic_entry_t*)pos)->type);
				tmp = pos;
			}
		}
		if (tmp) {
			delete_htable_entry((generic_entry_t*)tmp);
			tmp = NULL;
		}
	}

	foreach_listitem(pos, &loc_ls_tab.l_neigh) {
		if (tmp) {
			unlink_item(tmp);
			free(tmp);
			tmp = NULL;
		}

		if (now.tv_sec - ((loc_neigh_t*)pos)->ts.tv_sec > LOC_TIMEOUT){
			DEBUG(DEBUG_TABLE, "local neighbor entry %s removed\n",
			      print_ip(((loc_neigh_t*)pos)->addr));
			tmp = pos;
		}
	}

	if (tmp) {
		unlink_item(tmp);
		free(tmp);
	}
}
