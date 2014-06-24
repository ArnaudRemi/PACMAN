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

#ifndef _ADDR_MGR_H
#define _ADDR_MGR_H

#define ACN_MSG 1
#define LIST_REQ_MSG 2
#define LIST_REP_MSG 3
#define HINT_MSG     4

#define ACN_DIR1 0
#define ACN_DIR2 1

#define MAX_MSGADDR 1000
#define MAX_HINT_NEIGHBORS 1000

#define GUI_SOCKETNAME "/tmp/pacman.socket"
#define STAT_CONF 1
#define STAT_ADDR 2

typedef struct {
	u_int32_t orig_addr;
	u_int32_t seqn;
	int16_t type;
	u_int16_t n_cnt;
	u_int32_t neighbors[MAX_HINT_NEIGHBORS];
} ls_hint_t;

struct pacman_msg {
	u_int8_t type;
	char magic[3];
	union {
		u_int32_t addr[MAX_MSGADDR];
		ls_hint_t hint;
	} u;
};

void send_gui_msg(int type, u_int32_t addr, char *info);

void new_gui_client(int fd);
void recv_gui_msg(int fd);
int init_gui_socket();
void recv_pacman_msg(int fd);
void send_acn_msg(u_int32_t addr, u_int32_t next_hop);
void send_list_req_msg();
void resolve_conflict(u_int32_t addr, u_int32_t src_addr, char* reason, 
		      u_int32_t new_addr);
int init_pacman_msg_socket();
u_int32_t choose_new_addr();
void set_new_addr(u_int32_t addr);
int conf_ratelimit(u_int32_t addr, int direction);
void auto_conf(int send_);
u_int32_t is_acn_msg(char *buf, int len);
void send_hint_msg(u_int32_t addr, ls_entry_t *e);
void close_sockets();

extern int msg_fd;

#endif /* _ADDR_MGR_H */

