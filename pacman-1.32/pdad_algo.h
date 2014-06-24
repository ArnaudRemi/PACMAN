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

#ifndef _PDAD_ALGO_H
#define _PDAD_ALGO_H

extern int addr_changed;
extern struct timeval last_changed_ts;

int handle_generic_packet(ls_entry_t *e, u_int32_t src_addr, int incoming);
int do_pdad(ls_entry_t *e, u_int32_t src_addr);
int sn_thres_differ(u_int32_t s1, u_int32_t s2, int sn_thres);
float pdad_sn(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_snd(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_sne(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_sni(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_lp(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_enh(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_nh(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_mpr(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_empr(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
float pdad_sa(ls_entry_t *e, u_int32_t *conf_addr, float *alpha, float par);
int dup_detected(u_int32_t addr, float p, float alpha);
void consider_send_hint(u_int32_t conf_addr, ls_entry_t *e, int pdad_algo);
void print_pdad_stats();

#endif /* _PDAD_ALGO_H */
