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

/* added by remi arnaud */
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/netfilter.h>
#include <sys/types.h>
#include <sys/time.h>
#include <math.h>
#include <time.h>

#include "list.h"
#include "table.h"
#include "pacman.h"
#include "pdad_algo.h"
#include "addr_mgr.h"

int addr_changed = 0;
struct timeval last_changed_ts = {0, 0};
float min_snd_conf_stat = 9999;
float max_snd_noconf_stat = 0; 
struct timeval last_hint_msg = {0, 0};


int dup_detected(u_int32_t addr, float p, float alpha)
{
	conf_entry_t *c;

	if ((alpha>0) && (p>0)) {
		DEBUG(DEBUG_PDAD, "dup_detected: p=%.3f, alpha=%.3f\n",
		      p, alpha);

		if ((c = find_conf_entry(addr)) == NULL)
			c = new_conf_entry(addr);

		c->conf_p = alpha*p + (1 - alpha)*c->conf_p;
		dump_conflict_table();
		if(c->conf_p < CONF_P_THRES) return FALSE;
		return TRUE;
	}

	return FALSE;
}

int handle_generic_packet(ls_entry_t *e, u_int32_t src_addr, int incoming)
{
	list_t *pos;


	/* use outgoing packets to update our local neighbors table */
	if(!incoming) {
		if(e->orig_addr == loc_ls_tab.addr) {
			update_addr_list(e->orig_addr);
			loc_ls_tab.seqn[e->type] = e->seqn;
			foreach_listitem(pos, &e->neighbors)
				update_loc_neighbor(((neighbors_t*)pos)->addr,
						    ((neighbors_t*)pos)->linkcode);
			insert_ls_entry(e);
			if(debug & DEBUG_PDAD) dump_loc_ls_tab();
		}
		return NF_ACCEPT;
	}
			
	/* use src_addr of incoming packets to update local neighbors table */
	update_loc_neighbor(src_addr, LC_NONE);

	/* update ADDR LIST with all addresses in this ls_entry */
	update_addr_list(src_addr);
	update_addr_list(e->orig_addr);
	foreach_listitem(pos, &e->neighbors)
		update_addr_list(((neighbors_t*)pos)->addr);

	/* use incoming packets for PDAD */
	return do_pdad(e, src_addr);
}


int do_pdad(ls_entry_t *e, u_int32_t src_addr)
{
	u_int32_t conflict_addr;
	int i;
	float p, alpha;
	ls_entry_t *old_e;
	int res = NF_ACCEPT;

	if(debug & DEBUG_PDAD) {
		dump_linkstate_table();
		DEBUG(DEBUG_PDAD, "\ncurrent do_pdad() ls_entry:\n");
		print_linkstate_entry(e);
	}

	if((old_e = find_ls_entry(e->orig_addr, e->type))) {
                if ((e->ts.tv_sec - old_e->ts.tv_sec) > max_ips[e->type]) {
                        DEBUG(DEBUG_PDAD, "do_pdad(): packet ignored due to "
                              "large inter-packet spacing: %is\n",
                              (int)(e->ts.tv_sec - old_e->ts.tv_sec));
                        insert_ls_entry(e);
                        return NF_ACCEPT;
                }
        }

	for(i=0; i<MAX_PDAD_ALGO; i++) {
		if(!pa[i].active) continue;

		p = pa[i].pdad_func(e, &conflict_addr, &alpha, pa[i].par);

		if (dup_detected(conflict_addr, p, alpha)) {
			if(debug & DEBUG_PDAD_CONF) {
				dump_linkstate_table();
				dump_loc_ls_tab();
				DEBUG(DEBUG_PDAD_CONF, "\ncurrent do_pdad()"
				      "ls_entry:\n");
				print_linkstate_entry(e);
			}

			PRINTF("%s: Duplicate Address (%s) detected\n"
				,pa[i].name, print_ip(conflict_addr));
			pa[i].stats++;

			send_gui_msg(STAT_CONF, conflict_addr, pa[i].name);

			resolve_conflict(conflict_addr,src_addr,pa[i].name,0);
			res = NF_DROP;
		}
	}

	if(res == NF_DROP) {
		free(e);
		return NF_DROP;
	}

	/* no conflict: update ls_table and accept packet */
	if(e->orig_addr != loc_ls_tab.addr) insert_ls_entry(e);
	return NF_ACCEPT;
}

/* return TRUE in case of sequence number wrap-arounds */
int sn_wraparound(u_int32_t s1, u_int32_t s2, int sn_thres)
{
	u_int32_t w = protocols[rt_protocol].sn_max - sn_thres;

	if (((s1 > w) && (s2 < sn_thres )) || ((s2 > w) && (s1 < sn_thres)))
		return TRUE;

	return FALSE;
}

/* return TRUE if s1 and s2 differ by more than sn_thres */
int sn_thres_differ(u_int32_t s1, u_int32_t s2, int sn_thres)
{
	u_int32_t snd;
	u_int32_t sn_max = protocols[rt_protocol].sn_max;

	if (s1 > s2)
		snd = min(s1 - s2,sn_max-s1+s2);
	else
		snd = min(s2 - s1,sn_max-s2+s1);

	/* gather sn_thres stats */
	if (snd > sn_thres)
		min_snd_conf_stat = min(min_snd_conf_stat,
					(float)snd/sn_thres);
	else
		max_snd_noconf_stat = max(max_snd_noconf_stat,
					  (float)snd/sn_thres);

	return(snd > sn_thres);
}

float pdad_nh(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par)
{
	loc_neigh_t *ln;
	struct timeval now;

	*alpha = 0;

	/* addr(A) is in LS, orig_addr in LS was not our neighbor */

	/* if our address isn't part of e accept the packet */
	if (search_ls_neighbor(e, loc_ls_tab.addr) == NULL) return 0;

	/* if orig_addr was not our neighbor during the last nh_thres
	   seconds, drop the packet */
	  
	if ((ln = search_loc_ls_tab(e->orig_addr)) != NULL) {
		gettimeofday(&now, NULL);
		if ((now.tv_sec - ln->ts.tv_sec) <= t_d)
			return 0;
	}

	/* address conflict detected */
	*conf_addr = loc_ls_tab.addr;
	*alpha = 1;
	return 1;
}

float pdad_mpr(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par)
{
	loc_neigh_t *ln;
	struct timeval now;

	*alpha = 0;

	/* addr(A) is in LS, orig_addr in LS was not our neighbor */

	/* if our address isn't part of e accept the packet */
	if (search_ls_neighbor(e, loc_ls_tab.addr) == NULL) return 0;

	/* if orig_addr was not our neighbor during the last mpr_thres
	   seconds, drop the packet */
	  
	if ((ln = search_loc_ls_tab(e->orig_addr)) != NULL) {
		gettimeofday(&now, NULL);
		if ((now.tv_sec - ln->ts.tv_sec) <= t_d) {
			/* conflict, if e is a TC and we didn't
			   select e->orig_addr as MPR */
			if(!((e->type == LS_TYPE1) && (ln->linkcode == LC_NOMPR)))
				return 0;
		}
	}

	/* address conflict detected */
	*conf_addr = loc_ls_tab.addr;
	*alpha = 1;
	return 1;
}

float pdad_lp(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par)
{
	ls_entry_t *old_e;
	float p;

	*alpha = par;

	/* orig_addr = addr(A), |LS1 - LS2| > lp_thres */
        if ((old_e = find_ls_entry(e->orig_addr, e->type)) != NULL) {
		p = ls_differ(e, old_e, 1024);

		if ((p == -1) || ((p == 0) && (e->seqn == old_e->seqn))) {
			/* ignore duplicate packets and packets with less
			   than 2 LS-addresses */
			*alpha = 0;
			return 0;
		}
		if (p > 0) {
			/* possible address conflict */
			*conf_addr = e->orig_addr;
			return (p / (e->n_cnt + old_e->n_cnt));
		}
	}
	return 0;
}

float pdad_sn(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float sn_rate)
{
	float sn_thres;

	*alpha = 1;
	sn_thres = sn_rate*t_d;

	/* SN: orig_addr = addr(A), SN > SN(A) */
	if (e->orig_addr == loc_ls_tab.addr) {
		if ((e->seqn > loc_ls_tab.seqn[e->type]) &&
		    (!sn_wraparound(e->seqn, loc_ls_tab.seqn[e->type], sn_thres))) {
			/* address conflict detected */
			*conf_addr = e->orig_addr;
			return 1;
		}
	}
	
	*alpha = 0;
	return 0;
}

float pdad_snd(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float snd_rate)
{
	ls_entry_t *old_e;
	float snd_thres;

	*alpha = 1;

	if((old_e = find_ls_entry(e->orig_addr, e->type)) != NULL) {
		/* SND: orig_addr = addr(A), |SN1 - SN2| > snd_tresh */
		snd_thres = (e->ts.tv_sec - old_e->ts.tv_sec + t_d)*snd_rate;
		if (sn_thres_differ(e->seqn, old_e->seqn, snd_thres)) {
			/* address conflict detected */
			*conf_addr= e->orig_addr;
			return 1;
		}
	}
	
	*alpha = 0;
	return 0;
}

float pdad_sne(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float sne_thres)
{
	ls_entry_t *old_e;

	*alpha = 1;

	if ( (old_e = find_ls_entry(e->orig_addr, e->type)) != NULL) {
		/* SNE: orig_addr = addr(A), SN1 = SN2, LS1 != LS2 */
		if ((e->seqn == old_e->seqn) && (ls_differ(e, old_e, 1)!=0)) {
			/* address conflict detected */
			*conf_addr = e->orig_addr;
			return 1;
		}
	}

	*alpha = 0;
	return 0;
}

float pdad_sni(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float sni_rate)
{
	ls_entry_t *old_e;
	float sni_thres;

	*alpha = 1;

	if ( (old_e = find_ls_entry(e->orig_addr, e->type)) != NULL) {
		/* SNI: orig_addr = addr(A), type = HELLO, SN1 > SN2 */
		sni_thres = (e->ts.tv_sec - old_e->ts.tv_sec + t_d)*sni_rate;
		if ((old_e->seqn > e->seqn) &&
			   (e->type == LS_TYPE2) &&
			   (!sn_wraparound(old_e->seqn, e->seqn, sni_thres))) {
			/* address conflict detected */
			*conf_addr= e->orig_addr;
			return 1;
		}
	}
	
	*alpha = 0;
	return 0;
}


float pdad_sa(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float dummy)
{
	/* conflict, if we rx a packet with our address as source address */
	if (e->type == SA_RCVD) {
		*conf_addr = e->orig_addr;
		*alpha = 1;
		return 1;
	}
	*alpha = 0;
	return 0;
}

float pdad_enh(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par)
{
	ls_entry_t *corr_e;
	list_t *pos;
	struct timeval now;

	*alpha = 0;

	/* only look at OLSR TC msgs */
	if(e->type != LS_TYPE1) return 0;

	DEBUG(DEBUG_PDAD, "ENH: TC msg from %s\n", print_ip(e->orig_addr));
	
	foreach_listitem(pos, &e->neighbors) {
		DEBUG(DEBUG_PDAD, "    %s: ",
		      print_ip(((neighbors_t*)pos)->addr));
		
		/* find HELLO msgs corresponding to neighbors in this TC msg */
		corr_e = find_ls_entry(((neighbors_t*)pos)->addr, LS_TYPE2);

		DEBUG(DEBUG_PDAD, "%s\n", corr_e ? "found\n" : "not found\n");

		/* ignore our own HELLO msgs */
		if ((corr_e==NULL) || (corr_e->orig_addr==loc_ls_tab.addr))
			continue;

		DEBUG(DEBUG_PDAD, "ENH: corresponding HELLO msg found.\n");
		
		/* no conflict, if orig_addr is really a neighbor of corr_e
		   and corr_e is part of the MPRS of orig_addr */ 
		if (search_ls_neighbor(corr_e, e->orig_addr)) continue;

		DEBUG(DEBUG_PDAD, "ENH: HELLO / TC mismatch.\n");

		/* looks like a conflict with corr_e - check HELLO timestamp */
		gettimeofday(&now, NULL);
		if ((now.tv_sec - corr_e->ts.tv_sec) > max_ips[corr_e->type])
			continue;

		/* possible address conflict detected */
		DEBUG(DEBUG_PDAD, "ENH: TC received from %s ",
		      print_ip(e->orig_addr));
		DEBUG(DEBUG_PDAD, "with neighbor %s,\n",
		      print_ip(corr_e->orig_addr));
		DEBUG(DEBUG_PDAD, "but last HELLO says %s ",
		      print_ip(e->orig_addr));
		DEBUG(DEBUG_PDAD, "is not a neighbor of %s\n",
		      print_ip(corr_e->orig_addr));

		consider_send_hint(corr_e->orig_addr, e, ENH);
	}

	DEBUG(DEBUG_PDAD, "ENH: leaving pdad_enh()\n");
	return 0;
}

float pdad_empr(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par)
{
	ls_entry_t *corr_e;
	list_t *pos;
	struct timeval now;
	neighbors_t *neigh;

	*alpha = 0;

	/* only look at OLSR TC msgs */
	if(e->type != LS_TYPE1) return 0;

	DEBUG(DEBUG_PDAD, "EMPR: TC msg from %s\n", print_ip(e->orig_addr));
	
	foreach_listitem(pos, &e->neighbors) {
		DEBUG(DEBUG_PDAD, "    %s: ",
		      print_ip(((neighbors_t*)pos)->addr));
		
		/* find HELLO msgs corresponding to neighbors in this TC msg */
		corr_e = find_ls_entry(((neighbors_t*)pos)->addr, LS_TYPE2);

		DEBUG(DEBUG_PDAD, "%s\n", corr_e ? "found\n" : "not found\n");

		/* ignore our own HELLO msgs */
		if ((corr_e==NULL) || (corr_e->orig_addr==loc_ls_tab.addr))
			continue;

		DEBUG(DEBUG_PDAD, "EMPR: corresponding HELLO msg found.\n");
		
		/* no conflict, if orig_addr is really a neighbor of corr_e
		   and corr_e is part of the EMPRS of orig_addr */ 
		if ((neigh = search_ls_neighbor(corr_e, e->orig_addr))
		    && (neigh->linkcode != LC_NOMPR))
			continue;

		DEBUG(DEBUG_PDAD, "EMPR: HELLO / TC mismatch.\n");

		/* looks like a conflict with corr_e - check HELLO timestamp */
		gettimeofday(&now, NULL);
		if ((now.tv_sec - corr_e->ts.tv_sec) > max_ips[corr_e->type])
			continue;

		/* possible address conflict detected */
		DEBUG(DEBUG_PDAD, "EMPR: TC received from %s ",
		      print_ip(e->orig_addr));
		DEBUG(DEBUG_PDAD, "with neighbor %s,\n",
		      print_ip(corr_e->orig_addr));
		DEBUG(DEBUG_PDAD, "but last HELLO says %s ",
		      print_ip(e->orig_addr));
		DEBUG(DEBUG_PDAD, "is not a neighbor of %s\n",
		      print_ip(corr_e->orig_addr));

		consider_send_hint(corr_e->orig_addr, e, EMPR);
	}
	
	DEBUG(DEBUG_PDAD, "EMPR: leaving pdad_empr()\n");
	return 0;
}

void consider_send_hint(u_int32_t conf_addr, ls_entry_t *e, int pdad_algo)
{
	struct timeval now, diff;
	
	/* limit rate of sent HINT_MSGs to 1/HINT_TIME */
	gettimeofday(&now, NULL);
	
	/* prevent overflows (if this is the first HINT_MSG) */
	if(last_hint_msg.tv_sec == 0) {
		diff.tv_sec = ceil(HINT_TIME/1000.0) + 1;
		diff.tv_usec = 0;
	} else
		timersub(&now, &last_hint_msg, &diff);
	
	if (abs((diff.tv_sec*1000 + diff.tv_usec/1000)) <= HINT_TIME) {
		DEBUG(DEBUG_MSG, "HINT_MSG dropped (ratelimit)\n");
		return;
	}
	
	last_hint_msg = now;
	
	send_hint_msg(conf_addr, e);
	pa[pdad_algo].stats++;
	send_gui_msg(STAT_CONF, conf_addr,
		     hide_hints_in_gui?"":pa[pdad_algo].name);
}



void print_pdad_stats()
{
	int i;

	PRINTF("pdad stats:\n\n");
	for(i=0; i<MAX_PDAD_ALGO; i++)
		PRINTF("%s_CNT: %i\n", pa[i].name, pa[i].stats);

	PRINTF("addr_changed: %i\n", addr_changed);
	PRINTF("addr_last_changed_ts: %li.%.06li\n\n", last_changed_ts.tv_sec,
		last_changed_ts.tv_usec);

	PRINTF("min_snd_conf_stat: %.02f\n", min_snd_conf_stat);
	PRINTF("max_snd_noconf_stat: %.02f\n", max_snd_noconf_stat);

	dump_loc_ls_tab();
}
