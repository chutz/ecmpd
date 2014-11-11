#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/types.h>

#include "log.h"

static int ping_sock;
static __be16 ping_id;

#define PING_SIG	0x4d504757

struct ping_msg {
	__be32 ifindex;
	__be32 sig;
};

static __be16 in_cksum(const __be16 *addr, register int len)
{
	register int nleft = len;
	register __be32 sum = 0;
	const __be16 *w = addr;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += htons((__u16)(*(char *)w) << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (__be16)~sum;
}

int send_ping(int ifindex, __be32 daddr)
{
	static struct sockaddr_in dest = {AF_INET, 0, };
	static char buf[sizeof(struct icmphdr) + sizeof(struct ping_msg)];
	static struct iovec iov = {buf, sizeof(buf)};
	static struct {
		struct cmsghdr cm;
		struct in_pktinfo ipi;
	} cmsg = {{sizeof(cmsg.cm) + sizeof(cmsg.ipi), SOL_IP, IP_PKTINFO}, };
	static struct msghdr msg = {&dest, sizeof(dest), &iov, 1,
				    &cmsg, sizeof(cmsg), 0};
	struct icmphdr *icmp = (struct icmphdr *)buf;
	struct ping_msg *pmsg = (struct ping_msg *)(icmp + 1);

	DBG("if %d daddr %s", ifindex, ip2str(daddr));

	dest.sin_addr.s_addr = daddr;
	cmsg.ipi.ipi_ifindex = ifindex;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = ping_id;
	icmp->un.echo.sequence = 0;
	icmp->checksum = 0;
	pmsg->ifindex = (__be32)ifindex;
	pmsg->sig = PING_SIG;
	icmp->checksum = in_cksum((__be16 *)buf, sizeof(buf));

	if (sendmsg(ping_sock, &msg, MSG_DONTROUTE) < 0) {
		ERROR("sendmsg %d %s %s",
		      ifindex, ip2str(daddr), strerror(errno));
		return -1;
	}
	return 0;
}

int recv_ping(int *ifindex, __be32 *daddr)
{
	static struct sockaddr_in src;
	static char buf[1500];
	struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct iphdr));
	struct ping_msg *pmsg = (struct ping_msg *)(icmp + 1);
	socklen_t srclen = sizeof(src);
	int len;

	len = recvfrom(ping_sock, buf, sizeof(buf), MSG_DONTWAIT,
		       (struct sockaddr *)&src, &srclen);
	if (len < sizeof(struct iphdr) + sizeof(*icmp)) {
		ERROR("recvmsg len %d %s", len, strerror(errno));
		return -1;
	}
	if (src.sin_family != AF_INET) {
		return -1;
	}
	if (icmp->un.echo.id != ping_id || icmp->type != ICMP_ECHOREPLY ||
	    icmp->un.echo.sequence != 0 || icmp->code != 0) {
		return -1;
	}
	if (len < sizeof(struct iphdr) + sizeof(*icmp) + sizeof(*pmsg)) {
		ERROR("msg too small");
		return -1;
	}
	/* do iphdr checksum as well */
	if (in_cksum((__be16 *)buf, len) != 0) {
		ERROR("checksum error");
		return -1;
	}
	if (pmsg->sig != PING_SIG) {
		ERROR("signature error");
		return -1;
	}

	*ifindex = (int)pmsg->ifindex;
	*daddr = src.sin_addr.s_addr;

	DBG("if %d daddr %s", *ifindex, ip2str(*daddr));
	return 0;
}

int open_ping(void)
{
	int one = 1;

	if ((ping_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		ERROR("socket %s", strerror(errno));
		return -1;
	}
	if (setsockopt(ping_sock, IPPROTO_IP, IP_TTL, &one, sizeof(one)) < 0) {
		ERROR("setsockopt IP_TTL %s", strerror(errno));
		goto err_out;
	}
	if (setsockopt(ping_sock,
		       IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) < 0) {
		ERROR("setsockopt IP_PKTINFO %s", strerror(errno));
		goto err_out;
	}
	ping_id = htons(getpid() & 0xFFFF);
	return ping_sock;

err_out:
	close(ping_sock);
	return -1;
}

void close_ping(void)
{
	close(ping_sock);
}
