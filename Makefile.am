SUBDIRS = ecmpd
EXTRA_DIST = autogen.sh README.md deploy resources

.PHONY: clean-all
clean-all: maintainer-clean
	-rm -f ecmpd/Makefile.in
	-rm -f Makefile.in aclocal.m4 configure config.h.in*
	-rm -rf autom4te.cache
	-rm -rf build-aux
