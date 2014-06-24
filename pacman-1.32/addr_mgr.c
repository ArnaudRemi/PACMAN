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

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>

#include "list.h"
#include "table.h"
#include "pacman.h"
#include "pdad_algo.h"
#include "addr_mgr.h"

int msg_fd;
int gui_fd;
int client_gui_fd = -1;
char last_changed_reason[36];
int addr_bits;

u_int32_t choose_new_addr()
{
	struct in_addr tmp_addr;
	u_int32_t addr;
	int try = 0;
	u_int32_t r = 0;
	double j, n;
	double pc;

	addr_bits = 0;
	/* get number of known addresses */
	n = est_node_count;
	j = n - count_htable_entries(CONF_TYPE);
	if (j<0) j=0;

	do {
		addr_bits++;
		r = (1<<addr_bits) - 1;
		if(r <= n)
			pc = 1.0;
		else
			pc = 1.0 - exp( -j - j*log(r)
					+ (r-n+j+0.5)*log(r-n+j)
					- (r-n+0.5)*log(r-n));

	} while((pc >= target_prob_conf) && (addr_bits < 16));

	DEBUG(DEBUG_MSG, "choose_new_addr(): j=%.0f, est_node_count=%.0f, "
	      "target_prob_conf=%.3f, pc=%.3f, addr_bits=%i\n", j, n,
	      target_prob_conf, pc, addr_bits);
		
	while(1) {
		try++;
		/* limit addr_bits to 16 (we use 169.254/16 as MANET_PREFIX) */
		if (try > 10 && addr_bits < 16 ) {
			addr_bits++;
			try = 1;
		}

		/* choose low-order 16 bits between 1 and (2^addr_bits)-1 */
		addr = 1 + (random() % ((1<<addr_bits ) - 1));

		/* add MANET_PREFIX */
		inet_aton("169.254.0.0", &tmp_addr);
		addr |= ntohl(tmp_addr.s_addr);

		/* return addr, if addr has not been heard recently */
		if(find_htable_entry(addr, ADDR_LIST_TYPE) == NULL)
			return addr;
	}
}

int conf_ratelimit(u_int32_t addr, int dir)
{
	struct timeval now, diff;
	conf_entry_t *c;

	/* don't drop broadcasts (LIST_REQ_MSG / LIST_REP_MSG) */
	if (addr == INADDR_BROADCAST) return FALSE;

	if ((c = find_conf_entry(addr)) == NULL)
		c = new_conf_entry(addr);

	DEBUG(DEBUG_MSG, "conf_ratelimit(%s, %i): ", print_ip(addr), dir);

	gettimeofday(&now, NULL);

	/* prevent overflows (if this is the first ACN_MSG) */
	if(c->acn_msg_ts[dir].tv_sec == 0) {
		diff.tv_sec = ceil(ACN_TIME/1000.0) + 1;
		diff.tv_usec = 0;
	} else
		timersub(&now, &c->acn_msg_ts[dir], &diff);

	if (abs((diff.tv_sec*1000 + diff.tv_usec/1000)) > ACN_TIME) {
		c->acn_msg_ts[dir] = now;
		c->ts = now;
		DEBUG(DEBUG_MSG, "FALSE: diff=%lims\n",diff.tv_sec*1000
		      + diff.tv_usec/1000); 
		return FALSE;
	}

	DEBUG(DEBUG_MSG, "TRUE: diff=%lims\n",diff.tv_sec*1000
	      + diff.tv_usec/1000); 

	return TRUE;
}

void resolve_conflict(u_int32_t addr, u_int32_t src_addr,
		     char *reason, u_int32_t new_addr)
{
	struct timeval now, diff;	
	ls_entry_t *e;

	if (addr != loc_ls_tab.addr) {
		if (loc_ls_tab.addr == 0) {
			DEBUG(DEBUG_MSG, "interface has no address:"
			      "acn_msg not sent\n");
			return;
		}
		if (!conf_ratelimit(addr, ACN_DIR1))
			send_acn_msg(addr, src_addr);
		return;
	}

	if(new_addr == 0) new_addr = choose_new_addr();

	update_addr_list(new_addr);

	gettimeofday(&now, NULL);
	timersub(&now, &last_changed_ts, &diff);

	/* ugly workaraound to fix libipq bug, if time between
	   address changes is to short */
	if((diff.tv_sec==0) && (diff.tv_usec<500*1000))
		usleep(500*1000-diff.tv_usec);	
		
	gettimeofday(&last_changed_ts, NULL);
	addr_changed++;
	strcpy(last_changed_reason, reason);

	PRINTF("ADDRESS CHANGED to %s (time: %li.%.06li)\n",print_ip(new_addr),
	       last_changed_ts.tv_sec, last_changed_ts.tv_usec);

	stop_rt_daemon();
	close(msg_fd);
	set_if_addr(dev, new_addr);
	/* remove entries with our old address from ls table */
	if ((e = find_ls_entry(loc_ls_tab.addr, LS_TYPE1)) != NULL)
		delete_htable_entry((generic_entry_t*)e);
	if ((e = find_ls_entry(loc_ls_tab.addr, LS_TYPE2)) != NULL)
		delete_htable_entry((generic_entry_t*)e);

	init_loc_ls_tab(new_addr);
	loc_ls_tab.seqn[LS_TYPE1] = 0;
	loc_ls_tab.seqn[LS_TYPE2] = 0;
	init_pacman_msg_socket();

	send_gui_msg(STAT_ADDR, 0, NULL);

	start_rt_daemon();
}

/* send packet with correct (interface) source address */
int pacman_sendto(int s, char *buf, size_t len, struct sockaddr *to,
		socklen_t tolen)
{
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct in_pktinfo pktinfo, *pktinfo_ptr;
	struct in_addr fromaddr;

	memset(&pktinfo, 0, sizeof(struct in_pktinfo));
	memset(&msgh, 0, sizeof(struct msghdr));
	fromaddr.s_addr = htonl(loc_ls_tab.addr);

	iov.iov_base = buf;
	iov.iov_len = len;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf;
	msgh.msg_controllen = sizeof (cmsgbuf);
	msgh.msg_name = to;
	msgh.msg_namelen = tolen;

	cmsg = CMSG_FIRSTHDR(&msgh);
	
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	pktinfo.ipi_spec_dst = fromaddr;;
	pktinfo_ptr = (struct in_pktinfo*)CMSG_DATA(cmsg);
	memcpy(pktinfo_ptr, &pktinfo, sizeof(struct in_pktinfo));
	
	/* delay msg between 0..MSG_JITTER ms */
	usleep(random() % (MSG_JITTER*1000));

	PRINTF("pacman_sendto() to %s\n",
	       print_ip(ntohl(((struct sockaddr_in *)to)->sin_addr.s_addr)));

	return sendmsg(s, &msgh, 0);
}

int init_gui_socket()
{
	struct sockaddr_un loc_addr;

	unlink(GUI_SOCKETNAME);

	if ((gui_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("init_gui_socket()");
		exit(1);
	}

	loc_addr.sun_family = AF_UNIX;
	strcpy(loc_addr.sun_path, GUI_SOCKETNAME);

	if(bind(gui_fd, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
		perror("init_gui_socket()");
		exit(1);
	}

	listen(gui_fd, 1);
	update_event_func(gui_fd, (event_func_t)new_gui_client);

	return gui_fd;
}

void new_gui_client(int fd)
{
	struct sockaddr_un ca;
	int ca_len;
      
	if(client_gui_fd > 0) close(client_gui_fd);

	client_gui_fd = accept(gui_fd, (struct sockaddr*)&ca,  &ca_len);

	update_event_func(client_gui_fd, (event_func_t)recv_gui_msg);
	send_gui_msg(STAT_ADDR, 0, NULL);
}

void recv_gui_msg(int fd)
{
	char buf[1024], out[1024], tmp[128];
	char *cptr;
	int len, index;
	unsigned int a;
	list_t *pos;
	u_int32_t addr;
	
	if ((len = recv(fd, (char*)&buf, sizeof(buf), 0)) <  0) {
		perror("recv()");
		return;
	}

	if (len == 0) {
/*		FIXME: should close fd */
//		close(fd);
//		client_gui_fd=-1;
//		PRINTF("Connection closed...\n");
//		update_event_func(-1, (event_func_t)recv_gui_msg);
		return;
	}

	for(cptr = strtok(buf, "\n"); cptr!=NULL; cptr=strtok(NULL, "\n")) {
		if(cptr >= buf + len) return;

		PRINTF("recv_gui_msg: %s\n", cptr);
		if(strncasecmp("KILL", cptr, 4) == 0) {
			exit(0);
		} else if(strncasecmp("AUTO", cptr, 4) == 0) {
			resolve_conflict(loc_ls_tab.addr, 0, "AUTOCONF", 0);
		} else if(strncasecmp("CONF", cptr, 4) == 0) {
			sscanf(cptr, "CONF %s\n", tmp);
			if( (addr=inet_addr(tmp)) != INADDR_NONE)
				resolve_conflict(loc_ls_tab.addr, 0,
						 "MANUAL", ntohl(addr));
		} else if(strncasecmp("SETC", cptr, 4) == 0) {
			if(sscanf(cptr, "SETC %u\n",&a) > 0) {
				target_prob_conf = ((float)a) / 100.0;
			}
		} else if(strncasecmp("LIST", cptr, 4) == 0) {
			sprintf(out, "ADDR_LIST\n");
			for (index = 0; index < HTABLE_SIZE; index++) {
				foreach_listitem(pos, &(htable.lhead[index])) {
					if((IS_ADDR_LIST_ENTRY(pos)) && 
					   (strlen(out)+20<sizeof(out))){
						sprintf(tmp, "%s\n", print_ip(((generic_entry_t*)pos)->orig_addr));
						strcat(out, tmp);
					}
				}
			}
			sprintf(tmp, ".\n");
			strcat(out, tmp);
			if (send(client_gui_fd, (char*)&out,
					strlen(out), 0) < 0) {
				perror("send()");
				exit(1);
			} 
		}		
	}
}

void send_gui_msg(int type, u_int32_t addr, char *info)
{
	char buf[1024], tmp[1024];
	int len, i;
	struct timeval now, diff;

	if(client_gui_fd < 0) return;

	switch(type) {
	case STAT_ADDR:
		timersub(&last_changed_ts, &starttime, &diff);
		sprintf(buf, "STAT\nA:%s:%s:%li:%02li.%01li\n",
			print_ip(loc_ls_tab.addr), last_changed_reason,
			diff.tv_sec/60, diff.tv_sec%60, diff.tv_usec/100000);
		break;;
	case STAT_CONF:
		gettimeofday(&now, NULL);
		timersub(&now, &starttime, &diff);
		sprintf(buf, "STAT\nC:%s:%s:%li:%02li.%01li\n",
			print_ip(addr), info,
			diff.tv_sec/60, diff.tv_sec%60, diff.tv_usec/100000);
		break;;
	default:
		return;
	}

	for(i=0; i<MAX_PDAD_ALGO; i++) {
		sprintf(tmp, "%s:%i\n", pa[i].name, pa[i].stats);
		strcat(buf, tmp);
	}

	sprintf(tmp, "ADDR_CHANGES:%i\n", addr_changed);
	strcat(buf, tmp);
	sprintf(tmp, "ADDR_BITS:%i\n", addr_bits);
	strcat(buf, tmp);
	sprintf(tmp, "PC:%u\n", (unsigned int)(target_prob_conf*100.0));
	strcat(buf, tmp);
	sprintf(tmp, ".\n");
	strcat(buf, tmp);
	
	if ((len = send(client_gui_fd, (char*)&buf, strlen(buf), 0)) <  0) {
		perror("send()");
		exit(1);
	}
}

int init_pacman_msg_socket()
{
	struct sockaddr_in loc_addr;
	int val = 1;

	if ((msg_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("init_pacman_msg_socket()");
		exit(1);
	}

	if(setsockopt(msg_fd, SOL_SOCKET, SO_REUSEADDR, dev, sizeof(dev))) {
		perror("setsockopt");
		exit(1);
	}


	loc_addr.sin_family = AF_INET;
	loc_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	loc_addr.sin_port = htons(PACMAN_PORT);

	if(bind(msg_fd, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
		perror("init_pacman_msg_socket()");
		exit(1);
	}

	DEBUG(DEBUG_MSG, "Bind to device %s\n", dev);
	
/*	if(setsockopt(msg_fd, SOL_SOCKET, SO_BINDTODEVICE, dev, sizeof(dev))) {
		perror("setsockopt");
		exit(1);
	}
*/
	if(setsockopt(msg_fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val))) {
		perror("setsockopt");
		exit(1);
	}
	val = 1;
	if(setsockopt(msg_fd, SOL_IP,IP_PKTINFO, &val, sizeof(val))) {
		perror("setsockopt");
		exit(1);
	}
	update_event_func(msg_fd, (event_func_t)recv_pacman_msg);

	return msg_fd;
}

void close_sockets()
{
	if(client_gui_fd) close(client_gui_fd);
	if(gui_fd) close(gui_fd);
	if(msg_fd) close(msg_fd);

	unlink(GUI_SOCKETNAME);
}

void send_list_rep_msg()
{
	struct pacman_msg msg;
	struct sockaddr_in rem_addr;
	list_t *pos;
	int index;
	int i = 0;

	rem_addr.sin_family = AF_INET;
	rem_addr.sin_addr.s_addr = INADDR_BROADCAST;
	rem_addr.sin_port = htons(PACMAN_PORT);

	memcpy(&msg.magic, "PAC", 3);
	msg.type = LIST_REP_MSG;

	for (index = 0; index < HTABLE_SIZE; index++) {
		foreach_listitem(pos, &(htable.lhead[index])) {
			if ((IS_ADDR_LIST_ENTRY(pos)) && i<MAX_MSGADDR)
				msg.u.addr[i++] = htonl(((generic_entry_t*)pos)->orig_addr);
		}
	}

	pacman_sendto(msg_fd, (char*)&msg,
		    sizeof(msg) - sizeof(msg.u) + i*sizeof(msg.u.addr[0]),
		    (struct sockaddr *)&rem_addr, sizeof(rem_addr));
	DEBUG(DEBUG_MSG, "LIST_REP_MSG sent\n");
}

void send_list_req_msg()
{
	struct pacman_msg msg;
	struct sockaddr_in rem_addr;

	rem_addr.sin_family = AF_INET;
	rem_addr.sin_addr.s_addr = INADDR_BROADCAST;
	rem_addr.sin_port = htons(PACMAN_PORT);

	memcpy(&msg.magic, "PAC", 3);
	msg.type = LIST_REQ_MSG;

	if(pacman_sendto(msg_fd, (char*)&msg,
		  sizeof(msg) - sizeof(msg.u),
		  (struct sockaddr *)&rem_addr, sizeof(rem_addr)) < 0) {
		
		perror("send_list_req_msg()");
		exit(1);
	}
	DEBUG(DEBUG_MSG, "LIST_REQ_MSG sent\n");
}

void send_acn_msg(u_int32_t addr, u_int32_t next_hop)
{
	struct pacman_msg msg;
	struct sockaddr_in rem_addr;
	struct in_addr hop_addr;
	int name[] = {CTL_NET, NET_IPV4, NET_IPV4_CONF, NET_PROTO_CONF_ALL,
		      NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE};
	int namelen = 5;
	int oldval, newval = 1;
	size_t len = sizeof(oldval);
	char buf[40];
	int i = 0;

	rem_addr.sin_family = AF_INET;
	rem_addr.sin_addr.s_addr = htonl(addr);
	rem_addr.sin_port = htons(PACMAN_PORT);

	hop_addr.s_addr = htonl(next_hop);

	memcpy(&msg.magic, "PAC", 3);
	msg.type = ACN_MSG;
	msg.u.addr[0] = htonl(addr);

	/* pad to align LSRR addresses to 32 bit boundary */
	buf[i++] = IPOPT_NOP;
	/* use SSRR for direct neighbors, LSRR otherwise */
	buf[i++] = (addr == next_hop) ? IPOPT_SSRR : IPOPT_LSRR;
	/* total len of LSRR option */
	buf[i++] = 11;
	/* relative pointer to current address */
	buf[i++] = 4;
	/* copy source route addresses (last address must be dest_addr) */
	memcpy((char *)&buf[i], (char *)&hop_addr, sizeof(struct in_addr));
	i += sizeof(struct in_addr);
	memcpy((char *)&buf[i], (char *)&rem_addr.sin_addr.s_addr,
	       sizeof(struct in_addr));
	i += sizeof(struct in_addr);
	DEBUG(DEBUG_MSG, "setsockopt len: %i\n", i);
	if (setsockopt(msg_fd, IPPROTO_IP, IP_OPTIONS, buf, i) < 0)
		perror("setsockopt()");

	/* enable source routing sysctl */
	if(sysctl(name, namelen, (void*)&oldval, &len, (void*)&newval, len)) {
		perror("enable_source_routing");
		exit(1);
	}

	if(pacman_sendto(msg_fd, (char*)&msg, 12, (struct sockaddr *)&rem_addr,
		       sizeof(rem_addr)) < 0) {
		perror("send_acn_addr_msg()");
		exit(1);
	}

	/* reset IP_OPTIONS */
	if (setsockopt(msg_fd, IPPROTO_IP, IP_OPTIONS, NULL, 0) < 0)
		perror("setsockopt()");


	/* restore old source routing state */
	if(sysctl(name, namelen, (void*)&newval, &len, (void*)&oldval, len)) {
		perror("enable_source_routing");
		exit(1);
	}

	DEBUG(DEBUG_MSG, "ACN Message sent to %s.\n",
	      print_ip(addr));
}

void send_hint_msg(u_int32_t addr, ls_entry_t *e)
{
	struct pacman_msg msg;
	struct sockaddr_in rem_addr;
	int len, i=0;
	list_t *pos;
	int name[] = {CTL_NET, NET_IPV4, NET_IPV4_CONF, NET_PROTO_CONF_ALL,
		      NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE};
	int namelen = 5;
	int oldval, newval = 1;
	size_t vallen = sizeof(oldval);
	char buf[40];

	rem_addr.sin_family = AF_INET;
	rem_addr.sin_addr.s_addr = htonl(addr);
	rem_addr.sin_port = htons(PACMAN_PORT);

	memcpy(&msg.magic, "PAC", 3);
	msg.type = HINT_MSG;

	msg.u.hint.orig_addr = htonl(e->orig_addr);
	msg.u.hint.seqn = htonl(e->seqn);
	msg.u.hint.type = htons(e->type);
	msg.u.hint.n_cnt = htons(e->n_cnt);

	foreach_listitem(pos, &e->neighbors) {
		if(i >= MAX_HINT_NEIGHBORS) {
			PRINTF("Number of neighbors in HINT_MSG limited"
			       "to %i.\n", MAX_HINT_NEIGHBORS);
			break;
		}
		msg.u.hint.neighbors[i++] = htonl(((neighbors_t*)pos)->addr);
	}
	
	len = sizeof(msg) - sizeof(msg.u) + sizeof(msg.u.hint) -
		(MAX_HINT_NEIGHBORS-i)*sizeof(msg.u.hint.neighbors[0]);

	i=0;
	/* pad to align LSRR addresses to 32 bit boundary */
	buf[i++] = IPOPT_NOP;
	/* use SSRR for direct neighbors */
	buf[i++] = IPOPT_SSRR;
	/* total len of LSRR option */
	buf[i++] = 11;
	/* relative pointer to current address */
	buf[i++] = 4;
	/* copy source route addresses (last address must be dest_addr) */
	memcpy((char *)&buf[i], (char *)&rem_addr.sin_addr.s_addr,
	       sizeof(struct in_addr));
	i += sizeof(struct in_addr);
	memcpy((char *)&buf[i], (char *)&rem_addr.sin_addr.s_addr,
	       sizeof(struct in_addr));
	i += sizeof(struct in_addr);

	DEBUG(DEBUG_MSG, "setsockopt len: %i\n", i);
	if (setsockopt(msg_fd, IPPROTO_IP, IP_OPTIONS, buf, i) < 0)
		perror("setsockopt()");

	/* enable source routing sysctl */
	if(sysctl(name, namelen, (void*)&oldval, &vallen, (void*)&newval, vallen)) {
		perror("enable_source_routing");
		exit(1);
	}

	if(pacman_sendto(msg_fd, (char*)&msg, len, (struct sockaddr *)&rem_addr,
		       sizeof(rem_addr)) < 0) {
		perror("send_hint_msg()");
		exit(1);
	}

	/* reset IP_OPTIONS */
	if (setsockopt(msg_fd, IPPROTO_IP, IP_OPTIONS, NULL, 0) < 0)
		perror("setsockopt()");

	/* restore old source routing state */
	if(sysctl(name, namelen, (void*)&newval, &vallen, (void*)&oldval, vallen)) {
		perror("enable_source_routing");
		exit(1);
	}

	DEBUG(DEBUG_MSG, "HINT_MSG sent to %s.\n", print_ip(addr));
}

u_int32_t is_acn_msg(char *buf, int len)
{
	struct pacman_msg *msg;
	int minsize;

	msg = (struct pacman_msg *)buf;
	minsize = sizeof(struct pacman_msg) - sizeof(msg->u)+
		sizeof(msg->u.addr[0]);
	
	DEBUG(DEBUG_MSG, "MSG len: %i, minsize: %i, msg->type: %i\n",
	      len, minsize, msg->type);
	
	if (len < minsize) return 0;
	if (memcmp(&msg->magic, "PAC", 3) != 0) return 0;

	if (msg->type != ACN_MSG) return 0;

	return ntohl(msg->u.addr[0]);
}

void recv_pacman_msg(int fd)
{	
	struct pacman_msg msg;
	struct sockaddr_in rem_addr;
	int rlen, len, i = 0;
	int minsize;
	ls_entry_t *e;
	char buf[64];

	minsize = sizeof(msg) - sizeof(msg.u);

	rem_addr.sin_family = AF_INET;
	rem_addr.sin_port = htons(PACMAN_PORT);

	rlen = sizeof(rem_addr);
	if ((len = recvfrom(fd, (char*)&msg, sizeof(msg), 0,
			    (struct sockaddr *)&rem_addr, &rlen)) <  0) {
		perror("recvfrom()");
		exit(1);
	}

	DEBUG(DEBUG_MSG, "MSG from %s ",
	      print_ip(ntohl(rem_addr.sin_addr.s_addr)));
	DEBUG(DEBUG_MSG, "(our address is %s).\n",
			print_ip(loc_ls_tab.addr));

	if (len < minsize) {
		PRINTF("recv_pacman_msg(): MSG to short (%i)\n", len);
		return;
	}
	
	if (memcmp(&msg.magic, "PAC", 3) != 0) {
		PRINTF("recv_pacman_msg(): Invalid\n");
		return;
	}

	switch(msg.type) {
	case ACN_MSG:
		DEBUG(DEBUG_MSG, "ACN Message received from "
		      "%s.\n", print_ip(ntohl(rem_addr.sin_addr.s_addr)));
		snprintf(buf, sizeof(buf), "ACN from %s",
			 print_ip(ntohl(rem_addr.sin_addr.s_addr)));
		resolve_conflict(loc_ls_tab.addr, 0, buf, 0);
		break;;

	case LIST_REQ_MSG:
		/* don't reply with an invalid address (autoconf in progress)*/
		if(autoconf) return;
		DEBUG(DEBUG_MSG, "LIST_REQ_MSG received.\n");
		send_list_rep_msg();
		break;;

	case LIST_REP_MSG:
		DEBUG(DEBUG_MSG, "LIST_REP_MSG received:\n");
		while (len >= (minsize + (1+i)*sizeof(msg.u.addr[0]))) {
			DEBUG(DEBUG_MSG,"%s\n",print_ip(ntohl(msg.u.addr[i])));
			update_addr_list(ntohl(msg.u.addr[i++]));
		}
		break;;
	case HINT_MSG:
		DEBUG(DEBUG_MSG, "HINT_MSG received from %s.\n",
		      print_ip(ntohl(rem_addr.sin_addr.s_addr)));

		minsize += sizeof(msg.u.hint) -
			MAX_HINT_NEIGHBORS*sizeof(msg.u.hint.neighbors[0]);

		if (len < minsize) {
			PRINTF("received HINT_MSG is to short (%i)\n", len);
			return;
		}

		minsize += ntohs(msg.u.hint.n_cnt) *
			sizeof(msg.u.hint.neighbors[0]);

		if (len < minsize) {
			PRINTF("received HINT_MSG is to short (%i)\n", len);
			return;
		}

		e = new_ls_entry(ntohl(msg.u.hint.orig_addr),
				 ntohl(msg.u.hint.seqn),
				 ntohs(msg.u.hint.type));

		for(i=0; i<ntohs(msg.u.hint.n_cnt); i++)
			update_ls_neighbor(e, ntohl(msg.u.hint.neighbors[i]), LC_NONE);

		handle_generic_packet(e, ntohl(rem_addr.sin_addr.s_addr), 1);
		break;;
	default:
		DEBUG(DEBUG_MSG, "Unknown MSG type (%i)\n", msg.type);
	}
}
