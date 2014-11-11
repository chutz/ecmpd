#ifndef _ECMPD_MPGW_H
#define _ECMPD_MPGW_H

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/types.h>

#define MAX_MPGW	32

struct mpgw {
	__be32 gw_ip;
	char   gw_hw[ETH_ALEN];
	__be32 if_ip;
	char   if_hw[ETH_ALEN];
	int    if_id;
	int    state;
	struct timespec last_sent;
	struct timespec last_rcvd;
	int    timeout;
};

enum mpgw_state {
	MPGW_S_UNUSED = 0,
	MPGW_S_PROBE,
	MPGW_S_FAILED,
};

#define MASTER_PERIOD	1000
#define SLAVE_PERIOD	(MASTER_PERIOD + 10 + random() % (MASTER_PERIOD))
#define FAILED_PERIOD	(60000 + random() % 30000)

#define MAX_TRIES	3

void reset_mpgws(void);
void dump_mpgws(void);

struct mpgw *add_mpgw(__be32 addr, int ifindex);
struct mpgw *find_mpgw(__be32 addr, int ifindex);
int update_mpgw(struct mpgw *gw, enum mpgw_state newstate);

#endif
