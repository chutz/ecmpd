#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "mpgw.h"
#include "log.h"

static int poll_sock;
static int talk_sock;
static int talk_seq;

/* FIXME: buffer size enough? */
static char recv_buf[16384];

static struct rtattr *rta_find(struct rtattr *head, int len, int type)
{
	struct rtattr *rta;

	for (rta = head; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
		if (rta->rta_type == type)
			return rta;
	return NULL;
}

static int process_rt(struct nlmsghdr *nlh)
{
	int len;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct rtattr *rta;
	struct rtnexthop *nh;

	len = NLMSG_PAYLOAD(nlh, sizeof(*rtm));
	if (len < 0) {
		ERROR("invalid nlmsg_len %d", len);
		return -1;
	}
	if (rtm->rtm_family != AF_INET || rtm->rtm_scope >= RT_SCOPE_LINK)
		return 0;

	rta = rta_find(RTM_RTA(rtm), len, RTA_MULTIPATH);
	if (rta == NULL)
		return 0;

	for (len = RTA_PAYLOAD(rta), nh = RTA_DATA(rta);
	     len >= sizeof(*nh) && len >= nh->rtnh_len;
	     len -= RTNH_ALIGN(nh->rtnh_len), nh = RTNH_NEXT(nh)) {
		__be32 gw;

		rta = rta_find(RTNH_DATA(nh),
			nh->rtnh_len - RTNH_ALIGN(sizeof(*nh)), RTA_GATEWAY);
		if (rta == NULL) {
			ERROR("no gateway in nh info");
			return 0;
		}

		gw = *(__be32 *)RTA_DATA(rta);
		if (add_mpgw(gw, nh->rtnh_ifindex) == NULL)
			return -1;
	}

	return 0;
}

#define process_err(nlh) ({					\
	struct nlmsgerr *err = NLMSG_DATA(nlh);			\
	int rc __attribute__ ((unused));			\
								\
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {	\
		ERROR("nlerr msg truncated");			\
		rc = -1;					\
	} else if (err->error) {				\
		ERROR("nlerr %s", strerror(-err->error));	\
		rc = -1;					\
	}							\
	rc = 0;							\
})

int get_nhs(void)
{
	int len;
	struct nlmsghdr *nlh;
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg rtm;
	} req;

	reset_mpgws();

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++talk_seq;
	req.rtm.rtgen_family = AF_INET;

	if (send(talk_sock, (void*)&req, sizeof(req), 0) < 0) {
		ERROR("send %s", strerror(errno));
		return -1;
	}

	for (;;) {
		len = recv(talk_sock, recv_buf, sizeof(recv_buf), 0);
		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			ERROR("recv %s", strerror(errno));
			return -1;
		}
		if (len == 0) {
			ERROR("recv len == 0");
			return -1;
		}

		for (nlh = (struct nlmsghdr *)recv_buf; NLMSG_OK(nlh, len);
		     nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_seq != talk_seq) {
				ERROR("invalid seq %d", nlh->nlmsg_seq);
				continue;
			}

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				process_err(nlh);
				return -1;
			}
			if (nlh->nlmsg_type != RTM_NEWROUTE) {
				ERROR("invalid type %d", nlh->nlmsg_type);
				continue;
			}
			if (process_rt(nlh) < 0)
				return -1;
		}
	}
}

int update_neigh(int ifindex, __be32 ip, char* hw, int reachable)
{
	struct {
		struct nlmsghdr nlh;
		struct ndmsg ndm;
		struct nlattr nla_dst;
		__be32 dst;
		struct nlattr nla_hw;
		char hw[NLMSG_ALIGN(ETH_ALEN)];
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_NEWNEIGH;
	req.nlh.nlmsg_seq = ++talk_seq;
	req.nlh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ACK |
			       NLM_F_CREATE | NLM_F_REPLACE);

	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_state = reachable ? NUD_REACHABLE : NUD_FAILED;

	req.nla_dst.nla_len = sizeof(struct nlattr) + sizeof(__be32);
	req.nla_dst.nla_type = NDA_DST;
	req.dst = ip;

	req.nla_hw.nla_len = sizeof(struct nlattr) + ETH_ALEN;
	req.nla_hw.nla_type = NDA_LLADDR;
	memcpy(&req.hw, hw, ETH_ALEN);

	if (send(talk_sock, (void*)&req, sizeof(req), 0) < 0) {
		ERROR("send %s", strerror(errno));
		return -1;
	}

	for (;;) {
		int len;
		struct nlmsghdr *nlh;

		len = recv(talk_sock, recv_buf, sizeof(recv_buf), 0);
		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			ERROR("recv %s", strerror(errno));
			return -1;
		}
		if (len == 0) {
			ERROR("recv len == 0");
			return -1;
		}

		nlh = (struct nlmsghdr *)recv_buf;
		if (!NLMSG_OK(nlh, len)) {
			ERROR("invalid len %d", len);
			return -1;
		}
		if (nlh->nlmsg_seq != talk_seq) {
			ERROR("invalid seq %d", nlh->nlmsg_seq);
			return -1;
		}
		if (nlh->nlmsg_type != NLMSG_ERROR) {
			ERROR("invalid type %d", nlh->nlmsg_type);
			return -1;
		}
		return process_err(nlh);
	}
}

int recv_nl(void)
{
	struct sockaddr_nl saddr;
	socklen_t addrlen = sizeof(saddr);

	if (recvfrom(poll_sock, recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
		     (struct sockaddr *)&saddr, &addrlen) < 0) {
		ERROR("recvfrom %s", strerror(errno));
		return 0;
	}
	if (addrlen != sizeof(saddr)) {
		ERROR("invalid addr len");
		return 0;
	}
	if (saddr.nl_pid)
		return 0;

	get_nhs();
	return 1;
}

int open_nl(void)
{
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if ((talk_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		ERROR("socket talk_sock %s", strerror(errno));
		goto err_out;
	}
	if (connect(talk_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ERROR("connect talk_sock %s", strerror(errno));
		goto cleanup_talk;
	}
	if (getsockname(talk_sock, (struct sockaddr *)&addr, &addrlen) < 0) {
		ERROR("getsockname talk_sock %s", strerror(errno));
		goto cleanup_talk;
	}
	talk_seq = random();

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_ROUTE;

	if ((poll_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		ERROR("socket poll_sock %s", strerror(errno));
		goto cleanup_talk;
	}
	if (bind(poll_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ERROR("bind poll_sock %s", strerror(errno));
		goto cleanup_poll;
	}

	if (get_nhs() < 0)
		goto cleanup_poll;

	return poll_sock;

cleanup_poll:
	close(poll_sock);
cleanup_talk:
	close(talk_sock);
err_out:
	return -1;
}

void close_nl(void)
{
	close(poll_sock);
	close(talk_sock);
}
