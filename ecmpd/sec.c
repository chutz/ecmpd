#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBCAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/securebits.h>

#define err_exit(fmt, args...) ({fprintf(stderr, fmt, ##args); exit(1);})

static inline void set_cap(cap_t cap_p, cap_flag_t flag, cap_value_t cap)
{
	if (cap_set_flag(cap_p, flag, 1, &cap, CAP_SET) == -1)
		err_exit("set cap %d %d %s\n", flag, cap, strerror(errno));
}

static inline void clear_cap(cap_t cap_p, cap_flag_t flag, cap_value_t cap)
{
	if (cap_set_flag(cap_p, flag, 1, &cap, CAP_CLEAR) == -1)
		err_exit("clear cap %d %d %s\n", flag, cap, strerror(errno));
}

void drop_privilege(const char *user)
{
	struct passwd *pwd;
	cap_t cap_p;

	if (user == NULL || *user == '\0')
		err_exit("invalid user %s\n", user);
	errno = 0;
	pwd = getpwnam(user);
	if (pwd == NULL)
		err_exit("getpwnam %s %s\n", user, strerror(errno));

	if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS) == -1)
		err_exit("prctl securebits %s\n",  strerror(errno));

	cap_p = cap_init();
	if (cap_p == NULL)
		err_exit("cap_init %s\n", strerror(errno));

	set_cap(cap_p, CAP_PERMITTED, CAP_NET_RAW);
	set_cap(cap_p, CAP_PERMITTED, CAP_NET_ADMIN);
	set_cap(cap_p, CAP_PERMITTED, CAP_SETUID);
	set_cap(cap_p, CAP_PERMITTED, CAP_SETGID);
	set_cap(cap_p, CAP_EFFECTIVE, CAP_SETUID);
	set_cap(cap_p, CAP_EFFECTIVE, CAP_SETGID);
	if (cap_set_proc(cap_p) == -1)
		err_exit("cap_set_proc %s\n", strerror(errno));

	if (setgid(pwd->pw_gid) == -1)
		err_exit("error set gid %d %s\n", pwd->pw_gid, strerror(errno));
	if (setuid(pwd->pw_uid) == -1)
		err_exit("error set uid %d %s\n", pwd->pw_uid, strerror(errno));

	set_cap(cap_p, CAP_EFFECTIVE, CAP_NET_RAW);
	set_cap(cap_p, CAP_EFFECTIVE, CAP_NET_ADMIN);
	clear_cap(cap_p, CAP_EFFECTIVE, CAP_SETUID);
	clear_cap(cap_p, CAP_EFFECTIVE, CAP_SETGID);
	clear_cap(cap_p, CAP_PERMITTED, CAP_SETUID);
	clear_cap(cap_p, CAP_PERMITTED, CAP_SETGID);
	if (cap_set_proc(cap_p) == -1)
		err_exit("cap_set_proc %s\n", strerror(errno));

	cap_free(cap_p);
}

#endif

#ifdef HAVE_LIBSECCOMP

#include <string.h>
#include <errno.h>
#include <seccomp.h>

#include "log.h"

static int whitelist[] = {
	SCMP_SYS(brk),
	SCMP_SYS(close),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(connect),
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
	SCMP_SYS(getsockname),
	SCMP_SYS(ioctl),
	SCMP_SYS(lseek),
	SCMP_SYS(mmap),
	SCMP_SYS(munmap),
	SCMP_SYS(open),
	SCMP_SYS(poll),
	SCMP_SYS(read),
	SCMP_SYS(recvfrom),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sendmsg),
	SCMP_SYS(sendto),
	SCMP_SYS(setsockopt),
	SCMP_SYS(socket),
	SCMP_SYS(write),
};

int whitelist_syscalls(void)
{
	int i, rc = -1;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		ERROR("seccomp init failed");
		return rc;
	}

	for (i = 0; i < sizeof(whitelist)/sizeof(int); i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, whitelist[i], 0);
		if (rc < 0) {
			ERROR("seccomp rule add failed %s", strerror(-rc));
			goto out;
		}
	}

	rc = seccomp_load(ctx);
	if (rc < 0)
		ERROR("seccomp load failed %s", strerror(-rc));
out:
	seccomp_release(ctx);
	return rc;
}

#endif
