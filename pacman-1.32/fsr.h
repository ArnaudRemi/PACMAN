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

#ifndef _FSR_H
#define _FSR_H

struct fsr_tc_msg {
	u_int32_t d_addr;
	u_int16_t d_seqn;
	u_int16_t n_cnt;
	u_int32_t n_addr[1];
};

struct fsr_msg {
	u_int16_t len;
	u_int16_t res;
	struct fsr_tc_msg tc[1];
};

int parse_fsr_msg(char *msg, size_t cnt, u_int32_t src_addr, int incoming);

#endif /* _FSR_H */
