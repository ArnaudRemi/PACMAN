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

#ifndef _TABLE_H
#define _TABLE_H

#define HTABLE_SIZE 32
#define HASHMASK (HTABLE_SIZE-1)

#define SA_RCVD -1
#define LS_TYPE1 0
#define LS_TYPE2 1
#define CONF_TYPE 2
#define ADDR_LIST_TYPE 3

/* Link Codes (OLSR MPR Selection) */
#define LC_NONE 0
#define LC_NOMPR 1
#define LC_MPR 2

/* keep MPR state in should be t_d */
#define MPR_TRESH 15

#define IS_LS_ENTRY(x) ((((ls_entry_t*)x)->type == LS_TYPE1)||(((ls_entry_t*)x)->type == LS_TYPE2))

#define IS_CONF_ENTRY(x) (((conf_entry_t*)x)->type == CONF_TYPE)
#define IS_ADDR_LIST_ENTRY(x) (((generic_entry_t*)x)->type == ADDR_LIST_TYPE)

typedef struct {
	list_t l;
	u_int32_t orig_addr;
	int type;
	struct timeval ts;
	u_int32_t seqn;
	int n_cnt;
	list_t neighbors;
} ls_entry_t;

typedef struct {
	list_t l;
	u_int32_t orig_addr;
	int type;
	struct timeval ts;
	float conf_p;
	struct timeval acn_msg_ts[2];
} conf_entry_t;

typedef struct {
	list_t l;
	u_int32_t orig_addr;
	int type;
	struct timeval ts;
} generic_entry_t;

/*
typedef struct {
	union {
		generic_entry_t gen_e;
		ls_entry_t ls_e;
		conf_entry_t conf_e;
	} u;
} htable_entry_t;
*/

typedef struct {
	list_t l;
	u_int32_t addr;
	u_int8_t linkcode;
} neighbors_t;

typedef struct {
	u_int32_t addr;
	u_int32_t seqn[LS_TYPE2+1];
	list_t l_neigh;
} local_ls_t;

typedef struct {
	list_t l;
	u_int32_t addr;
	u_int8_t linkcode;
	struct timeval lc_ts;
	struct timeval ts;
} loc_neigh_t;

#define init_list(list) list.prev = list.next = &list

extern local_ls_t loc_ls_tab;

typedef struct {
	list_t lhead[HTABLE_SIZE];
} htable_t;

extern htable_t htable;

int is_bigger(list_t *a, list_t *b);
u_int32_t hash_ip_addr(u_int32_t ip);
char* print_ip(u_int32_t addr);
void print_linkstate_entry(ls_entry_t *e);
void init_loc_ls_tab(u_int32_t addr);
void init_htable();
void dump_linkstate_table();
void dump_loc_ls_tab();
void dump_conflict_table();
void print_conflict_entry(conf_entry_t *c);
void update_addr_list(u_int32_t addr);
void* find_htable_entry(u_int32_t addr, int type);
u_int32_t count_htable_entries(int type);
void insert_htable_entry(generic_entry_t *g);
void insert_ls_entry(ls_entry_t *ls_entry);
void update_loc_neighbor(u_int32_t addr, u_int8_t linkcode);
void update_ls_neighbor(ls_entry_t *e, u_int32_t addr, u_int8_t linkcode);
void delete_htable_entry(generic_entry_t *g);
ls_entry_t* new_ls_entry(u_int32_t addr, u_int32_t seqn, int type);
conf_entry_t* new_conf_entry(u_int32_t addr);
void* find_htable_entry(u_int32_t addr, int type);
conf_entry_t* find_conf_entry(u_int32_t addr);
ls_entry_t* find_ls_entry(u_int32_t addr, int type);
int ls_differ(ls_entry_t *e1, ls_entry_t *e2, int max_diff);
neighbors_t* search_ls_neighbor(ls_entry_t *e, u_int32_t addr);
loc_neigh_t* search_loc_ls_tab( u_int32_t addr);
void table_cleanup_timer();

#endif /* _TABLE_H */

