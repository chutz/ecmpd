AC_INIT([ecmpd], [0.0.1])
AC_CONFIG_AUX_DIR(build-aux)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([foreign dist-xz])

: ${CFLAGS=""}
AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_WITH(cap,
  AS_HELP_STRING([--with-cap],
    [compile with the libcap to enable privilege dropping]),
  [], [with_cap=no])

AS_IF([test "x$with_cap" != xno],
  AC_CHECK_LIB(cap, cap_init, [],
    [AC_MSG_FAILURE([--with-cap was given, but libcap test failed])]))

AC_ARG_WITH(seccomp,
  AS_HELP_STRING([--with-seccomp],
    [compile with the libseccomp]),
  [], [with_seccomp=no])

AS_IF([test "x$with_seccomp" != xno],
  AC_CHECK_LIB(seccomp, seccomp_init, [],
    [AC_MSG_FAILURE([--with-seccomp was given, but libseccomp test failed])]))

AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [turn on debugging]),
  [case "${enableval}" in
     yes) debug=true ;;
     no)  debug=false ;;
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
   esac],
  [debug=false])

AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_CONFIG_FILES([Makefile ecmpd/Makefile])
AC_OUTPUT
