dnl configure.ac for checkpassword-pam  -*- autoconf -*-
AC_REVISION($Id: configure.ac,v 1.9 2005/10/05 20:06:58 tyranny Exp $)

define(previous_version, 0.99)
define(current_version, 1.00rc)

AC_PREREQ(2.53)

AC_INIT(checkpassword-pam, current_version(), checkpasswd-pam-users@lists.sourceforge.net)
AM_INIT_AUTOMAKE(checkpassword-pam, current_version())
AM_MAINTAINER_MODE

AM_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR(checkpassword-pam.c)

AC_PROG_MAKE_SET
AC_PROG_CC

AC_C_CONST

# check that PAM libraries exist, together with libdl
AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(pam, pam_start)


AC_SUBST(PREVIOUS_VERSION, previous_version())

AC_CONFIG_FILES([Makefile checkpassword-pam.spec])
AC_OUTPUT
