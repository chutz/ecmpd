#ifndef _ECMPD_PING_H
#define _ECMPD_PING_H

#include <linux/types.h>

int open_ping(void);
void close_ping(void);
int recv_ping(int *ifindex, __be32 *daddr);
int send_ping(__be32 saddr, __be32 daddr);

#endif
