#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "log.h"

static int arp_sock;

int send_garp(int ifindex, __be32 sip, char *sha, __be32 tip, char *tha)
{
	static char buf[64];
	struct sockaddr_ll sll;
	struct arphdr *arp = (struct arphdr*)buf;
	char *p = (char *)(arp + 1);

	DBG("if %d sip %s sha %s", ifindex, ip2str(sip), hw2str(sha));

	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op  = htons(ARPOP_REPLY);

	memcpy(p, sha, ETH_ALEN);
	p += ETH_ALEN;
	memcpy(p, &sip, 4);
	p += 4;
	memcpy(p, tha, ETH_ALEN);
	p += ETH_ALEN;
	memcpy(p, &tip, 4);
	p += 4;

	memset(&sll, 0, sizeof(sll));
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = ifindex;
	sll.sll_halen = ETH_ALEN;
	memset(sll.sll_addr, 0xFF, ETH_ALEN);

	if (sendto(arp_sock, buf, p - buf, 0,
		   (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		ERROR("sendto if %d %s", ifindex, strerror(errno));
		return -1;
	}

	return 0;
}

int recv_arp(int *ifindex, __u16 *type, __u16 *op,
	     __be32 *sip, char *sha, __be32 *tip, char *tha)
{
	int len;
	static char buf[1024];
	struct sockaddr_ll sll;
	socklen_t sll_len = sizeof(sll);
	struct arphdr *arp = (struct arphdr*)buf;
	char *p = (char *)(arp + 1);

	len = recvfrom(arp_sock, buf, sizeof(buf), MSG_DONTWAIT,
		       (struct sockaddr *)&sll, &sll_len);
	if (len < 0) {
		ERROR("recvfrom %s", strerror(errno));
		return -1;
	}
	if (len < sizeof(*arp) ||
	    (arp->ar_op != htons(ARPOP_REQUEST) &&
	     arp->ar_op != htons(ARPOP_REPLY)) ||
	    arp->ar_pln != 4 ||
	    arp->ar_pro != htons(ETH_P_IP) ||
	    arp->ar_hln != ETH_ALEN ||
	    len < sizeof(*arp) + 2*4 + 2*ETH_ALEN) {
		ERROR("invalid message");
		return -1;
	}

	*ifindex = sll.sll_ifindex;
	*type = sll.sll_pkttype;
	*op = ntohs(arp->ar_op);
	memcpy(sha, p, ETH_ALEN);
	memcpy(sip, p + ETH_ALEN, 4);
	memcpy(tha, p + ETH_ALEN + 4, ETH_ALEN);
	memcpy(tip, p + ETH_ALEN + 4 + ETH_ALEN, 4);

	return 0;
}

int open_arp(void)
{
	if ((arp_sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))) < 0) {
		ERROR("socket %s", strerror(errno));
		return -1;
	}
	return arp_sock;
}

void close_arp(void)
{
	close(arp_sock);
}
