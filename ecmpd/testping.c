#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "ping.h"
#include "log.h"

#define err_exit(msg) ({perror(msg); exit(-2);})

#define timeval_to_ms(tv) \
	(((tv).tv_sec * 1000000 + (tv).tv_usec) / 1000.0)

#define adj_timeval(tv) \
	({(tv).tv_sec--; (tv).tv_usec += 1000000; \
	  (tv).tv_sec += (tv).tv_usec / 1000000;  \
	  (tv).tv_usec = (tv).tv_usec % 1000000;})

int foreground = 1;

static int nsent;
static int nrcvd;

static void summary(void)
{
	printf("\n--- ping statistics ---\n");
	printf("%d packets transmitted, %d received, %d%% packet loss\n",
	       nsent, nrcvd, (nsent - nrcvd) * 100 / nsent);
}

static void exit_handler(int type)
{
	summary();
	exit(0);
}

static void process_ping(void)
{
	int ifindex;
	__be32 dst;

	if (recv_ping(&ifindex, &dst) < 0)
		return;
	nrcvd++;
	printf("rcvd %s from if %d\n", ip2str(dst), ifindex);
}

static void loop(int ifindex, __be32 dst)
{
	int s, ret;
	struct timeval timeout, now, last = {0, 0};
	fd_set rfds, readers;

	printf("PING %s from if %d\n", ip2str(dst), ifindex);

	if ((s = open_ping()) < 0)
		exit(-1);

	FD_ZERO(&readers);
	FD_SET(s, &readers);
	for (;;) {
		ret = gettimeofday(&now, NULL);
		if (ret == -1)
			err_exit("gettimeofday");

		timeout.tv_sec = last.tv_sec + 1 - now.tv_sec;
		timeout.tv_usec = last.tv_usec - now.tv_usec;
		adj_timeval(timeout);

		if (timeout.tv_sec < 0) {
			last = now;
			timeout.tv_sec = 1;
			timeout.tv_usec = 0;
			if (send_ping(ifindex, dst) == 0)
				nsent++;
		}

		memcpy(&rfds, &readers, sizeof(rfds));
		ret = select(s + 1, &rfds, NULL, NULL, &timeout);
		if (ret == -1 && errno != EINTR)
			err_exit("select");
		if (ret == 1)
			process_ping();
	}
}

int main(int argc, char *argv[])
{
	int ifindex = 0;
	struct in_addr dst;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "%s dstip [ ifindex ]\n", argv[0]);
		return -1;
	}
	if (inet_pton(AF_INET, argv[1], &dst) != 1) {
		fprintf(stderr, "invalid dstip\n");
		return -1;
	}
	if (argc == 3)
		ifindex = atoi(argv[2]);

	signal(SIGINT, exit_handler);
	signal(SIGTERM, exit_handler);
	loop(ifindex, dst.s_addr);

	return 0;
}
