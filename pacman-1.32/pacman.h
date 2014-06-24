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

#ifndef _PACMAN_H
#define _PACMAN_H

#define VERSION "1.32"

/* enable multicast support */
/* #define MCAST_ENABLED 1 */

#define MAX_EVENTS 4

#define MAX_RT_PROTOCOLS 3

#define OLSR_D3 0
#define OLSR 1
#define FSR 2

#define DROP 0
#define ACCEPT 1

#define FALSE 0
#define TRUE 1

#define MAX_PDAD_ALGO 10
#define SA 0
#define SN 1
#define SND 2
#define SNE 3
#define SNI 4
#define LP 5
#define NH 6
#define ENH 7
#define MPR 8
#define EMPR 9

#define CONF_P_THRES 0.95
#define PACMAN_PORT 10099

/* estimated number of nodes in the network */
#define EST_NODE_COUNT 50;

/* tolerated probability that an address conflict occurs */ 
#define TARGET_PROB_CONF 0.5;

/* default max. distribution time in s */
#define DEFAULT_T_D 30

/* time in milliseconds to wait for replies after sending a LIST_REQ_MSG */
#define LISTWAIT_INT 200

/* msg jitter in ms */
#define MSG_JITTER 20

/* minimum time between two ACN_MSG in ms */
#define ACN_TIME 500

/* minimum time between two HINT_MSG in ms */
#define HINT_TIME 2000

/* all following times are in seconds */
#define LOC_TIMEOUT 150
#define HTABLE_TIMEOUT 300
#define TIMER_INT 150      /* = min(LOC_TIMROUT, HTABLE_TIMEOUT) */

#define DEBUG(t, fmt, args...) if(debug & t) fprintf(stderr, fmt, ##args)
#define PRINTF(fmt, args...) fprintf(stderr, fmt, ##args)

#define DEBUG_PDAD_CONF 1<<0
#define DEBUG_MSG 1<<1
#define DEBUG_PDAD 1<<2
#define DEBUG_MAIN 1<<3
#define DEBUG_INPUT 1<<4
#define DEBUG_TABLE 1<<5
#define DEBUG_OLSR 1<<6
#define DEBUG_FSR 1<<7

typedef void (*event_func_t) (int);
typedef int (*parse_rt_func_t) (char *msg, size_t len,
				u_int32_t src_addr, int incoming);

struct rt_prots {
	char *name;		        /* protocol name */
	u_int16_t port;			/* udp port */
	u_int32_t sn_max;		/* sequence number size */ 
	parse_rt_func_t parse_rt_func;	/* parser function */
	float def_par[MAX_PDAD_ALGO];   /* default PDAD parameters */
	int max_ips[LS_TYPE2 + 1];	/* max allowed inter-packet-spacing */
};

typedef float (*pdad_func_t) (ls_entry_t *e, u_int32_t *conf_addr,
			      float *alpha, float par);
struct pdad_algo {
	char *name;                     /* algorithm name */
	pdad_func_t pdad_func;          /* pdad function ptr */
	u_int8_t active;                /* active flag */
	float par;                      /* algorithm parameter */
  	int stats;                      /* statistics counter */
};

extern const struct rt_prots protocols[MAX_RT_PROTOCOLS];
extern struct pdad_algo pa[MAX_PDAD_ALGO];

extern int rt_protocol;

extern u_int32_t est_node_count;
extern float target_prob_conf;

extern int debug;
extern int hide_hints_in_gui;
extern int max_ips[LS_TYPE2+1];
extern char *dev;
extern u_int32_t netmask;
extern long autoconf;
extern int timer_expired;
extern struct timeval starttime;
extern int t_d;


int add_event_func(int fd, event_func_t func);
int update_event_func(int fd, event_func_t func);
void start_rt_daemon();
void stop_rt_daemon();

#define max(a,b) (a > b) ? a : b
#define min(a,b) (a < b) ? a : b

u_int32_t get_if_addr(char *dev);
u_int32_t set_if_addr(char *dev, u_int32_t addr);

#endif /* _PACMAN_H */
