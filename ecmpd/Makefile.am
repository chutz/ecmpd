if DEBUG
AM_CFLAGS = -Wall -O0 -g -DDEBUG
else
AM_CFLAGS = -Wall -O2
endif

sbin_PROGRAMS = ecmpd
ecmpd_SOURCES = main.c \
	mpgw.c nl.c ping.c arp.c sec.c \
	mpgw.h nl.h ping.h arp.h sec.h log.h

check_PROGRAMS = testnl testarp testping
testnl_SOURCES = testnl.c mpgw.c nl.c
testarp_SOURCES = testarp.c arp.c
testping_SOURCES = testping.c ping.c
