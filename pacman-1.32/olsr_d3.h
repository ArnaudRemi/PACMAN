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

#ifndef _OLSR_D3_H
#define _OLSR_D3_H

/* OLSR Message Types */
#define HELLO_PACKET 1
#define TC_PACKET 2

/* OLSR Link Types */
#define ASYM_LINK 1
#define SYM_LINK 2
#define MPR_LINK 3

/* ls_entry_t Types */
#define TC LS_TYPE1
#define HELLO LS_TYPE2

struct olsr_d3_msg {
	u_int8_t msg_type;
	u_int8_t flags;
	u_int16_t msg_size;
};

struct hello_link_d3_msg {
	u_int8_t linktype;
	u_int8_t res;
	u_int16_t len;
	u_int32_t neigh_addr[1];
};

struct hello_d3_msg {
	u_int16_t msg_seqn;			/* Message Sequence Number */
	u_int16_t mpr_seqn;			/* MPR Sequence Number */
	struct hello_link_d3_msg link_msg[1];
};

struct tc_d3_msg {
	u_int16_t msg_seqn;		/* Message Sequence Number */
	u_int16_t mssn;			/* MPR Selector Sequence Number MSSN */
	u_int8_t hop_count;
	u_int8_t res[3];
	u_int32_t orig_addr;		/* Originator Address */
	u_int32_t mpr_s[1];		/* Multipoint Relay Selector Address */
};		

struct olsr_d3_packet {
	u_int16_t len;
	u_int16_t res;
	struct olsr_d3_msg first_msg;
};

int parse_olsr_d3_msg(char *msg, size_t len, u_int32_t src_addr, int incoming);

#endif /* _OLSR_D3_H */
