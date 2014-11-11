#include <stdio.h>
#include <arpa/inet.h>

#include "nl.h"
#include "mpgw.h"
#include "log.h"

#define err_exit(msg) ({perror(msg); exit(-2);})

int foreground = 1;

int main(int argc, char *argv[])
{
	int ifindex, reachable;
	struct in_addr ip;
	char hw[ETH_ALEN];

	if (open_nl() < 0)
		return -1;

	if (argc == 1) {
		if (get_nhs() < 0)
			return -1;
		dump_mpgws();
		return 0;
	}
	if (argc != 5) {
		fprintf(stderr, "%s ifindex ip hw reachable\n", argv[0]);
		return -1;
	}
	ifindex = atoi(argv[1]);
	if (inet_pton(AF_INET, argv[2], &ip) != 1) {
		fprintf(stderr, "invalid ip\n");
		return -1;
	}
	if (sscanf(argv[3], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &hw[0], &hw[1], &hw[2], &hw[3], &hw[4], &hw[5]) != 6) {
		fprintf(stderr, "invalid hw\n");
		return -1;
	}
	reachable = atoi(argv[4]);
	return update_neigh(ifindex, ip.s_addr, hw, reachable);
}
