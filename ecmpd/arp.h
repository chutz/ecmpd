#ifndef _ECMPD_ARP_H
#define _ECMPD_ARP_H

#include <linux/types.h>

int open_arp(void);
void close_arp(void);
int recv_arp(int *ifindex, __u16 *type, __u16 *op,
	     __be32 *sip, char *sha, __be32 *tip, char *tha);
int send_garp(int ifindex, __be32 sip, char *sha, __be32 tip, char *tha);

#endif
