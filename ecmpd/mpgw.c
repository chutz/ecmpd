#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "mpgw.h"
#include "log.h"

struct mpgw mpgws[MAX_MPGW];

static int fill_if_addrs(struct mpgw *gw)
{
	int sock, ret = -1;
	struct ifreq ifr;
	struct sockaddr_in saddr;
	socklen_t len;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ERROR("socket sock %s", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = gw->if_id;
	if (ioctl(sock, SIOCGIFNAME, &ifr)) {
		ERROR("SIOCGIFNAME %d %s", gw->if_id, strerror(errno));
		goto close_ret;
	}
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		ERROR("SIOCGIFHWADDR %s %s", ifr.ifr_name, strerror(errno));
		goto close_ret;
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		ERROR("invalid if %s", ifr.ifr_name);
		goto close_ret;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
		       ifr.ifr_name, strlen(ifr.ifr_name) + 1) < 0) {
		ERROR("setsockopt %s %s", ifr.ifr_name, strerror(errno));
		goto close_ret;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(1025);
	saddr.sin_addr.s_addr = gw->gw_ip;
	if (connect(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
		ERROR("connect to %s from %s %s",
		      ip2str(gw->gw_ip), ifr.ifr_name, strerror(errno));
		goto close_ret;
	}
	len = sizeof(saddr);
	if (getsockname(sock, (struct sockaddr*)&saddr, &len) < 0) {
		ERROR("getsockname %s %s", ifr.ifr_name, strerror(errno));
		goto close_ret;
	}

	ret = 0;
	memcpy(gw->if_hw, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	gw->if_ip = saddr.sin_addr.s_addr;

close_ret:
	close(sock);
	return ret;
}

void reset_mpgws(void)
{
	memset(mpgws, 0, sizeof(mpgws));
}

void dump_mpgws(void)
{
	int i;

	INFO("# gw_ip gw_hw if_ip if_hw if_id state timeout");
	for (i = 0; i < MAX_MPGW; i++) {
		struct mpgw *gw = &mpgws[i];
		static char buf[4096];
		size_t off = 0;

		if (gw->state == MPGW_S_UNUSED)
			continue;
		off += snprintf(buf + off, sizeof(buf) - off, "%s %s",
				ip2str(gw->gw_ip), hw2str(gw->gw_hw));
		off += snprintf(buf + off, sizeof(buf) - off, " %s %s",
				ip2str(gw->if_ip), hw2str(gw->if_hw));
		snprintf(buf + off, sizeof(buf) - off, " %d %d %d",
			 gw->if_id, gw->state, gw->timeout);
		INFO("%s", buf);
	}
}

struct mpgw *add_mpgw(__be32 addr, int ifindex)
{
	int i, j = -1;
	struct timespec now;

	for (i = 0; i < MAX_MPGW; i++) {
		if (mpgws[i].state == MPGW_S_UNUSED) {
			if (j == -1)
				j = i;
			continue;
		}
		if (mpgws[i].gw_ip == addr && mpgws[i].if_id == ifindex)
			return &mpgws[i];
	}

	if (j == -1) {
		ERROR("not enough memory");
		return NULL;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		ERROR("clock_gettime %s", strerror(errno));
		return NULL;
	}

	memset(&mpgws[j], 0, sizeof(mpgws[j]));
	mpgws[j].gw_ip = addr;
	mpgws[j].if_id = ifindex;
	if (fill_if_addrs(&mpgws[j]) < 0)
		return NULL;
	mpgws[j].last_sent = now;
	mpgws[j].last_rcvd = now;
	update_mpgw(&mpgws[j], MPGW_S_PROBE);

	srandom(mpgws[j].if_ip);
	return &mpgws[j];
}

struct mpgw *find_mpgw(__be32 addr, int ifindex)
{
	int i;

	for (i = 0; i < MAX_MPGW; i++) {
		if (mpgws[i].state == MPGW_S_UNUSED)
			continue;
		if (mpgws[i].gw_ip == addr && mpgws[i].if_id == ifindex)
			return &mpgws[i];
	}
	return NULL;
}

int update_mpgw(struct mpgw *gw, enum mpgw_state newstate)
{
	if (gw->state == newstate)
		return 0;

	INFO("%s if %d state %d", ip2str(gw->gw_ip), gw->if_id, newstate);

	gw->state = newstate;

	if (gw->state == MPGW_S_PROBE)
		gw->timeout = SLAVE_PERIOD;
	else
		gw->timeout = FAILED_PERIOD;
	return 1;
}
