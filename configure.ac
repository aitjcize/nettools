#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([synclotius], [0.1.0], [aitjcize@gmail.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/synflood.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([net], [libnet_init],, AC_MSG_ERROR([You need libnet1 to build $PACKAGE]))
AC_CHECK_LIB([pcap], [pcap_open_live],, AC_MSG_ERROR([You need libpcap to build $PACKAGE]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
