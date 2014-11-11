#ifndef _ECMPD_LOG_H
#define _ECMPD_LOG_H

#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include <linux/types.h>

extern int foreground;

#ifdef DEBUG

#define DBG(fmt, args...) ({						\
	if (foreground)	{						\
		struct timeval tv;					\
		gettimeofday(&tv, NULL);				\
		fprintf(stderr, "%ld.%06ld [dbg] %s: " fmt "\n",	\
			tv.tv_sec, tv.tv_usec,				\
			__func__, ##args);				\
	} else 								\
		syslog(LOG_DEBUG,					\
		       "{\"appname\": \"mpgwd\", \"msg\": \"%s "	\
		       fmt "\"}", __func__, ##args);			\
})

#else

#define DBG(fmt, args...)

#endif

#define ERROR(fmt, args...) ({						\
	if (foreground)	{						\
		struct timeval tv;					\
		gettimeofday(&tv, NULL);				\
		fprintf(stderr, "%ld.%06ld [error] %s: " fmt "\n",	\
			tv.tv_sec, tv.tv_usec,				\
			__func__, ##args);				\
	} else								\
		syslog(LOG_ERR,						\
		       "{\"appname\": \"mpgwd\", \"msg\": \"%s "	\
		       fmt "\"}", __func__, ##args);			\
})

#define INFO(fmt, args...) ({						\
	if (foreground)	{						\
		struct timeval tv;					\
		gettimeofday(&tv, NULL);				\
		fprintf(stderr, "%ld.%06ld [info] " fmt "\n",		\
			tv.tv_sec, tv.tv_usec,				\
			##args);					\
	} else								\
		syslog(LOG_INFO,					\
		       "{\"appname\": \"mpgwd\", \"msg\": "		\
		       fmt "\"}", ##args);				\
})

static inline void dump(char *data, int len)
{
	int i;

	printf("%02hhx ", data[0]);
	for (i = 1; i < len; i++) {
		if ((i % 8) == 0)
			printf(" ");
		if ((i % 16) == 0)
			printf("\n");
		printf("%02hhx ", data[i]);
	}
	printf("\n");
}

static inline char* ip2str(__be32 ip)
{
	static char buf[16];
	unsigned char *p = (unsigned char *)&ip;

	snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
		 p[0], p[1], p[2], p[3]);
	return buf;
}

static inline char* hw2str(char *hw)
{
	static char buf[18];

	snprintf(buf, sizeof(buf), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		 hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
	return buf;
}

#endif
