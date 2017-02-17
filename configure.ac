AC_PREREQ(2.57)
AC_INIT(rdd, [2.0.7], [rdd@holmes.nl])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_ARG_ENABLE([tracing],
	AC_HELP_STRING([--enable-tracing],
		[enable tracing (default: no)]),
	[if test $enableval = yes; then
		AC_DEFINE(RDD_TRACING, 1, [Define to enable tracing.])
	 fi])

AC_ARG_ENABLE([console],
	AC_HELP_STRING([--disable-console],
		[do not use the console device /dev/tty (default: no)]),
	[if test $enableval = yes; then
		AC_DEFINE(RDD_CONSOLE, 1, [Define for console usage.])
	 fi],
	AC_DEFINE(RDD_CONSOLE, 1, [Define for console usage.]))

AC_ARG_ENABLE([raw-device],
	AC_HELP_STRING([--enable-raw-device],
		[Experimental support reading from raw devices (Linux-specific) (default: no)]),
	[if test $enableval = yes; then
		AC_DEFINE(RDD_RAW, 1, [Define for raw-device support.])
	 fi])

AC_ARG_ENABLE([gui],
	AC_HELP_STRING([--enable-gui],
		[Enable GTK-2.0 GUI for rdd (default: no)]),
	[case $enableval in
	 yes) gui=yes
              AC_DEFINE(RDD_GUI, 1, [Define for GUI support.])
	      ;;
	 no)  gui=no
	      ;;
	 *)   AC_MSG_ERROR(bad value ${enableval} for --enable-gui)
              ;;
         esac])

AC_DEFUN([AM_PATH_LIBGLADE_2_0], [
	AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	LIBGLADE_CFLAGS=`$PKG_CONFIG --cflags libglade-2.0`
	LIBGLADE_LIBS=`$PKG_CONFIG --libs libglade-2.0`
	AC_SUBST(LIBGLADE_CFLAGS)
	AC_SUBST(LIBGLADE_LIBS)
])

AM_PATH_GTK_2_0
AM_PATH_LIBGLADE_2_0

AC_PROG_CC
AC_PROG_RANLIB
AC_ISC_POSIX

AM_CONDITIONAL(GCC_COMPILER, test x${GCC} = xyes)
AM_CONDITIONAL(RDD_GUI, test x$gui = xyes)

AC_CHECK_PROGS(PYTHON, [python python2.4 python2.3 python2.2], [python])

AC_STDC_HEADERS
AC_CHECK_HEADERS([pwd.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([time.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/utsname.h])
AC_CHECK_HEADERS([openssl/blowfish.h])
AC_CHECK_HEADERS([fcntl.h], [], [],
[#include <sys/types.h>
#include <sys/stat.h>
])
AC_CHECK_HEADERS([openssl/crypto.h], [], [],
[#include <sys/types.h>
])
AC_CHECK_HEADERS([openssl/md5.h], [], [],
[#include <sys/types.h>
])
AC_CHECK_HEADERS([openssl/sha.h], [], [],
[#include <sys/types.h>
])
AC_CHECK_HEADERS([inttypes.h])
AC_CHECK_TYPES([uint16_t, uint32_t, uint64_t], [], [],
[#include <inttypes.h>
])

AC_SYS_LARGEFILE

AC_CHECK_LIB(crypto, MD5_Init)
AC_CHECK_LIB(z, gzdopen)
AC_CHECK_LIB(m, log)
AC_CHECK_TYPES([socklen_t], , ,
[#include <sys/types.h>
#include <sys/socket.h>
])
AC_CHECK_TYPES([u_int16_t, u_int32_t, u_int64_t], , ,
[#include <sys/types.h>
])

AC_CONFIG_FILES([Makefile src/Makefile gui/Makefile test/Makefile])
AC_CONFIG_FILES([test/trunmd5blockfilter.sh
		 test/ttcpwriter.sh
		 test/tmsgprinter.sh],
		[chmod +x test/*.sh])

AC_OUTPUT
