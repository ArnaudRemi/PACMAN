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
#include "fsr.h"
#include "pacman.h"
#include "pdad_algo.h"

int parse_fsr_tc_msg(struct fsr_tc_msg *t, int incoming, u_int32_t src_addr)
{
	int i;
	ls_entry_t *e;

	/* fsrd 0.3.6 BUG: addresses are in x86 host byte order (LSB)! */

	e = new_ls_entry(t->d_addr, ntohs(t->d_seqn), LS_TYPE1);
	for (i = 0; i < ntohs(t->n_cnt); i++)
		update_ls_neighbor(e, t->n_addr[i], LC_NONE);

	return handle_generic_packet(e, src_addr, incoming);
}

int parse_fsr_msg(char *msg, size_t cnt, u_int32_t src_addr, int incoming)
{
	struct fsr_msg *m;
	struct fsr_tc_msg *t;
	int tlen;
	int res = NF_ACCEPT;

	m = (struct fsr_msg *)msg;
	DEBUG(DEBUG_FSR, "FSR msg size: %i\n",ntohs(m->len) );

	if ((cnt < (sizeof(struct fsr_msg)) - 4) || (cnt != ntohs(m->len)))
		return 0;
	
	/* point to first tc entry */
	t = &(m->tc[0]);
	cnt -= (char*)t - (char*)m;

	while (cnt >= (sizeof(struct fsr_tc_msg) - sizeof(t->n_addr))) {

		tlen = (ntohs(t->n_cnt)-1)*sizeof(t->n_addr) +
		                                 sizeof(struct fsr_tc_msg);
		if (cnt < tlen ) break;
		if (parse_fsr_tc_msg(t, incoming, src_addr) == NF_DROP)
			res = NF_DROP;

		cnt -= tlen;
		t = (struct fsr_tc_msg*)((char*)t + tlen);
	}
	
	return res;
}
