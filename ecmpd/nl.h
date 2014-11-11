#ifndef _ECMPD_NL_H
#define _ECMPD_NL_H

#include <linux/types.h>

int open_nl(void);
void close_nl(void);
int recv_nl(void);
int get_nhs(void);
int update_neigh(int ifindex, __be32 ip, char* hw, int reachable);

#endif
