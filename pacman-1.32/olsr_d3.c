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

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netfilter.h>

#include "list.h"
#include "table.h"
#include "olsr_d3.h"
#include "pacman.h"
#include "pdad_algo.h"

int parse_hello_d3_msg(struct hello_d3_msg *m, int cnt, int incoming, u_int32_t src)
{
	struct hello_link_d3_msg *hlm;
	int i;
	ls_entry_t *e;
	u_int32_t ta;
	int res = NF_ACCEPT;

	DEBUG(DEBUG_OLSR, "parse_hello_d3_msg(), len: %u\n", cnt);

	if(cnt < (sizeof(struct hello_d3_msg) - sizeof(struct hello_link_d3_msg))) {
		fprintf(stderr, "HELLO message to short - len: %u!\n", cnt);
		return NF_ACCEPT;
	}

	/* use HELLO message to generate new ls_entry */
	e = new_ls_entry(src, ntohs(m->msg_seqn), HELLO);

	hlm = m->link_msg;
	
	/* skip hello msg header */
	cnt -= (char *)hlm - (char *)m;

	/* copy neighbors to HELLO ls_entry */
	while(cnt >= sizeof(struct hello_link_d3_msg)) {
		if (ntohs(hlm->len) > cnt) {
			fprintf(stderr, "HELLO LINK msg len field (%i) "
				"invalid!\n", ntohs(hlm->len));
			return NF_ACCEPT;
		}
			
		if ((hlm->linktype == SYM_LINK)||(hlm->linktype == MPR_LINK)) {
			for(i=0;ntohs(hlm->len)>=((char*)&hlm->neigh_addr[i+1]
						  -(char*)hlm); i++) {
				ta = ntohl(hlm->neigh_addr[i]);
				update_ls_neighbor(e, ta, LC_NONE);
			}				
		}
 
		cnt -= ntohs(hlm->len);
		hlm = (struct hello_link_d3_msg*)((char*)hlm + ntohs(hlm->len));
	}
	res = handle_generic_packet(e, src, incoming);

	return res;
}

int parse_tc_d3_msg(struct tc_d3_msg *m, int len, int incoming, u_int32_t src)
{
	ls_entry_t* e;
	int i;


	if(len < (sizeof(struct tc_d3_msg) - sizeof(u_int32_t))) {
		DEBUG(DEBUG_OLSR, "TC message to short - len: %u!\n", len);
		return NF_ACCEPT;
	}

	e = new_ls_entry(ntohl(m->orig_addr), ntohs(m->msg_seqn), TC);

	/* copy all neighbors to ls_entry_t *e */
	for (i=0; ((char*)&(m->mpr_s[i+1]) - (char*)m) <= len; i++)
		update_ls_neighbor(e, ntohl(m->mpr_s[i]), LC_NONE);

	return handle_generic_packet(e, src, incoming);
}

int parse_olsr_d3_msg(char *msg, size_t cnt, u_int32_t src_addr, int incoming)
{
	struct olsr_d3_packet *olsr_pkt;
	struct olsr_d3_msg *m;
	char *ptr;
	int len;
	int res = NF_ACCEPT;

	olsr_pkt = (struct olsr_d3_packet *)msg;

	if ((cnt<sizeof(struct olsr_d3_packet)) || (cnt != ntohs(olsr_pkt->len)))
		return 0;
	
	m = &(olsr_pkt->first_msg);

	/* skip packet header */
	cnt -= (char *)m - msg;

	while (cnt > sizeof(struct olsr_d3_msg)) {

		DEBUG(DEBUG_OLSR, "msg_size: %u\n", ntohs(m->msg_size));
		if ((ntohs(m->msg_size)) > cnt) {
			DEBUG(DEBUG_OLSR,"parse_olsr_d3_msg():msg_size wrong!\n");
			return NF_ACCEPT;
		}

		/* pointer to hello_msg / tc_msg */
		ptr = ((char *)m + sizeof(struct olsr_d3_msg));

		/* len of hello_msg / tc_msg */
		len = ntohs(m->msg_size) - sizeof(struct olsr_d3_msg);
		
		DEBUG(DEBUG_OLSR, "next_msg\n");

		switch(m->msg_type) {
			case HELLO_PACKET: 
				res = parse_hello_d3_msg((struct hello_d3_msg *)ptr,
						      len, incoming, src_addr);
				break;;

			case TC_PACKET:
				res = parse_tc_d3_msg((struct tc_d3_msg *)ptr, len,
						   incoming, src_addr);
				break;;
				
			default:
				DEBUG(DEBUG_OLSR, "parse_olsr_d3_msg(): "
				      "Unknown OLSR Message Type %i!", 
				      m->msg_type);
		}
		cnt -= ntohs(m->msg_size);
		m = (struct olsr_d3_msg*)((char*)m + ntohs(m->msg_size));
	}

	return res;
}
