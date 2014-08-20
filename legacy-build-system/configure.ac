AC_INIT(sleep-proxy, 0.1)
AC_CONFIG_SRCDIR([../src/emulateHost.cpp])
AM_INIT_AUTOMAKE
AC_PROG_CXX
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
m4_include([m4/ax_pthread.m4])
AX_CXX_COMPILE_STDCXX_11([noext], [mandatory])
AX_PTHREAD
AC_PROG_INSTALL
AC_DEFINE(NO_POSIX_SPAWN, 1)

AC_SEARCH_LIBS(pcap_open_live, pcap, ,AC_MSG_ERROR([libpcap not found]))
AC_CHECK_HEADER([pcap.h], ,AC_MSG_ERROR([pcap.h not found]))

AC_OUTPUT(Makefile)
