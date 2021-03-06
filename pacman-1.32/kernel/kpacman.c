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

//#include <linux/version.h>
//#include <linux/config.h>

//#ifdef LINUX_VERSION_CODE
//  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
//    #define KERNEL_2_6
//  #endif
//#endif
//
//#ifndef KERNEL_2_6
//  #define __KERNEL__
//  #define MODULE
//#endif
//
//#ifdef CONFIG_MODVERSIONS
//  #define MODVERSIONS
//  #ifdef KERNEL_2_6
//    #include <config/modversions.h>
//  #else
//    #include <linux/modversions.h>
//  #endif
//#endif

#define MCAST_ENABLED 0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h> 
#include <linux/udp.h>

#ifdef MCAST_ENABLED
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#endif

#undef htonl
#undef htons
#undef ntohl
#undef ntohs
#define htonl(x) __cpu_to_be32(x)
#define htons(x) __cpu_to_be16(x)
#define ntohl(x) __be32_to_cpu(x)
#define ntohs(x) __be16_to_cpu(x)

#define PDAD_PORT 10099

#define MULTICAST(x) (((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define LOCAL_MCAST(x) (((x) & htonl(0xFFFFFF00)) == htonl(0xE0000000))

unsigned int pdad_nf_hook(unsigned int hook,
				 struct sk_buff **skb,
				 const struct net_device *indev,
				 const struct net_device *outdev,
				 int (*okfn)(struct sk_buff *));

static struct nf_hook_ops nfh_pre =
{
	{ NULL, NULL},
	pdad_nf_hook,
//#ifdef KERNEL_2_6
	THIS_MODULE,
//#endif
	PF_INET,
	//NF_IP_PRE_ROUTING,
	NF_INET_PRE_ROUTING,
	NF_IP_PRI_FILTER + 1 
};

static struct nf_hook_ops nfh_out =
{
	{ NULL, NULL},
	pdad_nf_hook,
//#ifdef KERNEL_2_6
	THIS_MODULE,
//#endif
	PF_INET,
	//NF_IP_LOCAL_OUT,
	NF_INET_LOCAL_OUT,
	NF_IP_PRI_FILTER + 1
};

static u_int16_t port = 0;

static const char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

unsigned int pdad_nf_hook(unsigned int hook,
				 struct sk_buff **skb,
				 const struct net_device *indev,
				 const struct net_device *outdev,
				 int (*okfn)(struct sk_buff *))
{
        struct iphdr  *iph;
	struct udphdr *udp;

        iph = ip_hdr(*skb);

#ifdef MCAST_ENABLED	
	if(iph)
        {
                switch(hook) 
                {
		case NF_INET_LOCAL_OUT:
			if(iph->protocol == IPPROTO_IGMP)
				return NF_DROP;
/*			printk("protocol: %d\n", (*skb)->nh.iph->protocol); */
                        if(MULTICAST(iph->daddr) && 
                           !LOCAL_MCAST(iph->daddr))
				return NF_QUEUE;
                        break;
		default:
                        break;
                }
        }
#endif	

	if (iph && iph->protocol == IPPROTO_UDP) {
		udp = (struct udphdr *)((char *)iph +
					(iph->ihl<<2));
		switch(hook) {
		case NF_INET_PRE_ROUTING:
			if ((ntohs(udp->dest) == port) ||
			    (ntohs(udp->dest) == PDAD_PORT)) {
				/* drop incoming packets, sent by us */
				if ((*skb)->mark == 1)
					return NF_DROP;
				return NF_QUEUE;
			}
			break;;
		case NF_INET_LOCAL_OUT:
			if (ntohs(udp->dest) == port) {
				/* drop already marked packets, sent by us */
				if ((*skb)->mark == 1)
					return NF_DROP;

				(*skb)->mark = 1;
				return NF_QUEUE;
			} else if(ntohs(udp->dest) == PDAD_PORT) {
				(*skb)->mark = 1;
			}
			break;;
		}
	}
	
	return NF_ACCEPT;				 
}

int init_module()
{
	if (nf_register_hook(&nfh_pre) < 0) {
		printk("pdad netfilter hook registration error!\n");
		return -EINVAL;
	}

	if (nf_register_hook(&nfh_out) < 0) {
		printk("pdad netfilter hook registration error!\n");
		return -EINVAL;
	}
	
	return 0;	  
}

void cleanup_module()
{
	nf_unregister_hook(&nfh_pre);
	nf_unregister_hook(&nfh_out);
}

MODULE_LICENSE("GPL");
module_param(port, short, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(port, "UDP port to listen on");

