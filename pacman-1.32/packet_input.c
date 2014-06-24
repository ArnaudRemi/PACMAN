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
#include <stddef.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "libipq.h"
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "list.h"
#include "table.h"
#include "pacman.h"
#include "packet_input.h"
#include "pdad_algo.h"
#include "addr_mgr.h"
#ifdef MCAST_ENABLED
#include "mcast.h"
#endif

static struct ipq_handle *h;

void die()
{
	ipq_perror("packet_input");
	if(h) ipq_destroy_handle(h);
	h = NULL;
	exit(1);
}

void update_arp(u_int32_t src_addr, unsigned char hw_addr[8],
	   size_t hw_addrlen, char dev[IFNAMSIZ])
{
	struct arpreq ar;

	DEBUG(DEBUG_INPUT, "update arp entry of %s\n", print_ip(src_addr));

	memset(&ar, 0, sizeof(struct arpreq));
	memcpy(ar.arp_ha.sa_data, hw_addr, hw_addrlen);

	((struct sockaddr_in*)&ar.arp_pa)->sin_family = AF_INET;
	((struct sockaddr_in*)&ar.arp_pa)->sin_addr.s_addr = htonl(src_addr);

	memcpy(ar.arp_dev, dev, sizeof(dev));

	ar.arp_flags = ATF_COM;

	if (ioctl(msg_fd, SIOCSARP, &ar) != 0)
		perror("ioctl SIOCSARP:");
}

void handle_ipq_packet(ipq_packet_msg_t *m)
{
	struct iphdr *ip;
	struct udphdr *udp;
	
	u_int32_t src_addr;
	u_int32_t dst_addr;
	u_int16_t dport;
	u_int32_t addr;
	int incoming;
	int msg_len;
	char *msg;
	int res = NF_ACCEPT;
	ls_entry_t *e;

#ifdef MCAST_ENABLED
	char *payload = NULL;
#endif

	DEBUG(DEBUG_INPUT, "id: %lu, mark: %lu, timestamp: %lu, hook: %u, "
	      "indev: %s, outdev: %s, datalen: %d\n", m->packet_id, m->mark,
	      m->timestamp_sec, m->hook, m->indev_name, m->outdev_name,
	      m->data_len);

	/* decide if packet is incoming or outgoing */
	incoming = (((m->hook == 0)||(m->hook == 1)) ? 1:0 );

	ip = (struct iphdr *)m->payload;
	udp = (struct udphdr *) ((char *)ip + (ip->ihl<<2));

	/* ignore packets that don't contain a valid UDP header */
	msg_len = m->data_len - ( (char *)udp - (char *)ip +
				  sizeof(struct udphdr));
	if (msg_len < 0) goto set_verdict;

	msg = (char*) ((char *)udp + sizeof(struct udphdr));

	src_addr = ntohl(ip->saddr);
	dst_addr = ntohl(ip->daddr);

	dport = ntohs(udp->dest);

#ifdef MCAST_ENABLED
	if(isMulticastPacket(ip->daddr))
        {
		payload = malloc(m->data_len);
		memcpy(payload, m->payload, m->data_len);
		
		route_outgoing_multicast_packet(payload, ntohs(ip->tot_len));
		
		free(payload);
		
		res = NF_DROP;
		goto set_verdict;
        }
#endif

	/* incoming broadcast packets */
	if (incoming && ((dst_addr | netmask) == 0xffffffff)) {
		
		/* conflict, if we rx a packet with our address as source address */
		if (pa[SA].active && (src_addr == loc_ls_tab.addr)) {
			e = new_ls_entry(src_addr, 0, SA_RCVD);
			//usleep(500*1000);
			res = do_pdad(e, src_addr);
			goto set_verdict;
		}

		/* use broadcasts to update our arp cache */
		update_arp(src_addr, m->hw_addr, m->hw_addrlen, m->indev_name);
	}

	DEBUG(DEBUG_INPUT, "SRC: %s\n\n",
	      inet_ntoa(*((struct in_addr *)&ip->saddr)));
	
	if (dport == protocols[rt_protocol].port) {
		/* parse payload of UDP packet */
		res = protocols[rt_protocol].parse_rt_func(msg, msg_len,
							   src_addr, incoming);
	} else if (dport == PACMAN_PORT) {
		/* drop "dup addr msg", if same msg was recently sent */
		addr = is_acn_msg(msg, msg_len);
		if (addr && conf_ratelimit(addr, ACN_DIR2)) {
			DEBUG(DEBUG_MSG, "drop dup addr msg for "
			      "%s (ratelimit)\n", print_ip(addr));
			res = NF_DROP;
		}
	}
	
set_verdict:
	if(ipq_set_verdict(h, m->packet_id, res, 0, NULL) < 0) {
		fprintf(stderr, "ipq_set_verdict() < 0\n");
		die(h);	
	}
}

void packet_input(int fd)
{
	char buf[BUFSIZE];
	ipq_packet_msg_t *m;
	
	if(ipq_read(h, buf, BUFSIZE, 0) < 0) {
		perror("ipq_read()");
		return;
	}	
		
	switch(ipq_message_type(buf)) {
	case NLMSG_ERROR:
		fprintf(stderr, "Received error message %d\n",
			ipq_get_msgerr(buf));
		break;
		
	case IPQM_PACKET:
		m = ipq_get_packet(buf);
		handle_ipq_packet(m);
		break;
		
	default:
		fprintf(stderr, "packet_input(): Unknown message type!\n");
		break;
	}
}				
	                                                                    
void init_packet_input()
{

	h = ipq_create_handle(0, PF_INET);
	if (!h)
		die();
	/* IPQ_COPY_PACKET defini par ip_queue ! */
	if(ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE) < 0)
		die();
		
	add_event_func(h->fd, (event_func_t)packet_input);
}

void cleanup_packet_input()
{
	if(h) ipq_destroy_handle(h);
	h = NULL;
}
