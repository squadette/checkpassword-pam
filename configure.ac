dnl configure.ac for checkpassword-pam  -*- autoconf -*-
AC_REVISION($Id: configure.ac,v 1.2 2002/04/18 23:21:46 tyranny Exp $)

define(previous_version, none)
define(current_version, 0.95)

AC_PREREQ(2.50)
AC_PREREQ(2.52e)

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



AC_CONFIG_FILES([Makefile])
AC_OUTPUT
