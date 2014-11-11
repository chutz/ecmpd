#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/poll.h>

#include "mpgw.h"
#include "nl.h"
#include "ping.h"
#include "arp.h"
#include "sec.h"
#include "log.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

int foreground = 0;	/* logging to foreground or syslog */

static int gratuitous_arp = 0;
static int master_election = 0;

extern struct mpgw mpgws[MAX_MPGW];

static void usage(void)
{
	fprintf(stderr,
#ifdef HAVE_LIBCAP
		"Usage: mpgwd [ -u user] [ -a ] [ -m ] [ -h ]\n\n"
		"    -u  drop privilege to <user> and its group\n"
#define OPT_STR	"u:amhf"
#else
		"Usage: mpgwd [ -a ] [ -m ] [ -h ]\n\n"
#define OPT_STR	"amhf"
#endif
		"    -a  send gratuitous arp after receiving ping response\n"
		"    -m  skip sending ping when receiving garp from master\n"
		"    -h  print this message and quit\n\n");
	exit(1);
}

static void sig_dump(int signo)
{
	dump_mpgws();
}

static int process_ping(void)
{
	int ifindex;
	__be32 addr;
	struct mpgw *gw;

	if (recv_ping(&ifindex, &addr) < 0)
		return 0;
	if ((gw = find_mpgw(addr, ifindex)) == NULL)
		return 0;

	if (clock_gettime(CLOCK_MONOTONIC, &gw->last_rcvd) < 0) {
		ERROR("clock_gettime %s", strerror(errno));
		return 1;
	}
	if (memcmp(gw->gw_hw, "\x0\x0\x0\x0\x0\x0", ETH_ALEN) == 0)
		return 1;

	if (update_neigh(gw->if_id, gw->gw_ip, gw->gw_hw, 1) == 0)
		update_mpgw(gw, MPGW_S_PROBE);

	if (gratuitous_arp)
		send_garp(gw->if_id, gw->gw_ip,
			  gw->gw_hw, gw->if_ip, gw->if_hw);
	return 1;
}

static int process_arp(void)
{
	int ifindex;
	__u16 type, op;
	__be32 sip, tip;
	char sha[ETH_ALEN], tha[ETH_ALEN];
	struct mpgw *gw;

	if (recv_arp(&ifindex, &type, &op, &sip, sha, &tip, tha) < 0)
		return 0;
	if ((gw = find_mpgw(sip, ifindex)) == NULL)
		return 0;
	if (tip == gw->if_ip && type == PACKET_BROADCAST && op == ARPOP_REPLY)
		return 0;

	if (memcmp(gw->gw_hw, sha, ETH_ALEN)) {
		INFO("gw %s on if %d changed mac to %s",
		     ip2str(sip), ifindex, hw2str(sha));
		memcpy(gw->gw_hw, sha, ETH_ALEN);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &gw->last_rcvd) < 0) {
		ERROR("clock_gettime %s", strerror(errno));
		return 1;
	}

	if (update_neigh(gw->if_id, gw->gw_ip, gw->gw_hw, 1) == 0)
		update_mpgw(gw, MPGW_S_PROBE);

	if (master_election && type == PACKET_BROADCAST && op == ARPOP_REPLY) {
		/*
		 * Timeouts of regular hosts may flip back and forth.
		 * Master timeout never flips.  After several rounds,
		 * only the master has the smallest timeout.
		 *
		 * Don't bother to ntoh(ips) for comparison.
		 */
		if (tip < gw->if_ip)
			gw->timeout = SLAVE_PERIOD;
		else
			gw->timeout = MASTER_PERIOD;
	}

	return 1;
}

#define timespec_diff(old, new)				\
	(((new)->tv_sec - (old)->tv_sec) * 1000 +	\
	 ((new)->tv_nsec - (old)->tv_nsec) / 1000000)

static int refresh(void)
{
	int i, diff, timeout = MASTER_PERIOD;
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		ERROR("clock_gettime %s", strerror(errno));
		return timeout;
	}

	for (i = 0; i < MAX_MPGW; i++){
		struct mpgw *gw = &mpgws[i];

		if (gw->state == MPGW_S_UNUSED)
			continue;

		diff = timespec_diff(&gw->last_rcvd, &now);
		if (diff < gw->timeout) {
			diff = gw->timeout - diff;
			if (timeout > diff)
				timeout = diff;
			if (gw->timeout != MASTER_PERIOD)
				continue;
		}

		if (gw->state == MPGW_S_PROBE &&
		    diff > MAX_TRIES * gw->timeout &&
		    update_neigh(gw->if_id, gw->gw_ip, gw->gw_hw, 0) == 0) {
			update_mpgw(gw, MPGW_S_FAILED);
			memset(&gw->gw_hw, 0, sizeof(ETH_ALEN));
		}

		diff = timespec_diff(&gw->last_sent, &now);
		if (diff < gw->timeout) {
			diff = gw->timeout - diff;
			if (timeout > diff)
				timeout = diff;
			continue;
		}

		send_ping(gw->if_id, gw->gw_ip);
		gw->last_sent = now;
		if (timeout > gw->timeout)
			timeout = gw->timeout;
	}

	return timeout;
}

int main(int argc, char *argv[])
{
	int c;
	struct pollfd pfds[3];
	struct sigaction sa;
	int changed, timeout = MASTER_PERIOD;

	while ((c = getopt(argc, argv, OPT_STR)) != -1) {
		switch (c) {
		case 'a':
			gratuitous_arp = 1;
			break;
		case 'm':
			master_election = 1;
			break;
		case 'f':
			foreground = 1;
			break;
#ifdef HAVE_LIBCAP
		case 'u':
			drop_privilege(optarg);
			break;
#endif
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	if (argc != optind)
		usage();

	if (!foreground)
		openlog("mpgwd", LOG_PID | LOG_CONS, LOG_DAEMON);

	memset(pfds, 0, sizeof(pfds));
	pfds[0].fd = open_nl();
	pfds[1].fd = open_arp();
	pfds[2].fd = open_ping();

	for (c = 0; c < 3; c++) {
		if (pfds[c].fd < 0)
			exit(1);
		pfds[c].events = POLLIN;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_dump;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		ERROR("sigaction %s", strerror(errno));
		exit(1);
	}

#ifdef HAVE_LIBSECCOMP
	whitelist_syscalls();
#endif

	for (;;) {
		changed = 0;

		timeout = poll(pfds, 3, timeout);
		if (timeout < 0 && errno != EINTR)
			ERROR("poll %s", strerror(errno));

		if (timeout > 0) {
			if (pfds[0].revents & POLLIN)
				changed += recv_nl();
			if (pfds[1].revents & POLLIN)
				changed += process_arp();
			if (pfds[2].revents & POLLIN)
				changed += process_ping();
		}

		if (changed || timeout <= 0)
			timeout = refresh();
	}
}
