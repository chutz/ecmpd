#ifndef _ECMPD_SEC_H
#define _ECMPD_SEC_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBCAP
void drop_privilege(const char *user);
#endif

#ifdef HAVE_LIBSECCOMP
int whitelist_syscalls(void);
#endif

#endif
