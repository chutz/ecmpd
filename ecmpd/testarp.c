#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>

#include "arp.h"
#include "log.h"

#define err_exit(msg) ({perror(msg); exit(-2);})

#define timeval_to_ms(tv) \
	(((tv).tv_sec * 1000000 + (tv).tv_usec) / 1000.0)

#define adj_timeval(tv) \
	({(tv).tv_sec--; (tv).tv_usec += 1000000; \
	  (tv).tv_sec += (tv).tv_usec / 1000000;  \
	  (tv).tv_usec = (tv).tv_usec % 1000000;})

int foreground = 1;

static void process_arp(void)
{
	int ifindex;
	__u16 type, op;
	__be32 sip, tip;
	char sha[ETH_ALEN], tha[ETH_ALEN];

	if (recv_arp(&ifindex, &type, &op, &sip, sha, &tip, tha) < 0)
		return;

	printf("rcvd if %d type %hd op %hd\n", ifindex, type, op);
	printf("  sender hw %s ip %s\n", hw2str(sha), ip2str(sip));
	printf("  target hw %s ip %s\n", hw2str(tha), ip2str(tip));
}

static void loop(int ifindex, __be32 sip, char *sha, __be32 tip, char *tha)
{
	int s, ret;
	struct timeval timeout, now, last = {0, 0};
	fd_set rfds, readers;

	printf("ARP\n");

	if ((s = open_arp()) < 0)
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
			if (send_garp(ifindex, sip, sha, tip, tha) == 0)
				printf("sent\n");
		}

		memcpy(&rfds, &readers, sizeof(rfds));
		ret = select(s + 1, &rfds, NULL, NULL, &timeout);
		if (ret == -1 && errno != EINTR)
			err_exit("select");
		if (ret == 1)
			process_arp();
	}
}

int main(int argc, char *argv[])
{
	int ifindex = 0;
	struct in_addr sip, tip;
	char sha[ETH_ALEN], tha[ETH_ALEN];

	if (argc != 6) {
		fprintf(stderr, "%s ifindex sip sha tip tha\n", argv[0]);
		return -1;
	}
	ifindex = atoi(argv[1]);
	if (inet_pton(AF_INET, argv[2], &sip) != 1) {
		fprintf(stderr, "invalid sip\n");
		return -1;
	}
	if (sscanf(argv[3], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &sha[0], &sha[1], &sha[2], &sha[3], &sha[4], &sha[5]) != 6) {
		fprintf(stderr, "invalid sha\n");
		return -1;
	}
	if (inet_pton(AF_INET, argv[4], &tip) != 1) {
		fprintf(stderr, "invalid tip\n");
		return -1;
	}
	if (sscanf(argv[5], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &tha[0], &tha[1], &tha[2], &tha[3], &tha[4], &tha[5]) != 6) {
		fprintf(stderr, "invalid tha\n");
		return -1;
	}
	loop(ifindex, sip.s_addr, sha, tip.s_addr, tha);
	return 0;
}
