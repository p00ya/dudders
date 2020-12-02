dnl configure.ac -- configure template                  -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

## Copyright Dean Scarff
##
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License.

AC_PREREQ([2.69])
AC_INIT([dudders],[1.04],[https://github.com/p00ya/dudders])
AC_CONFIG_SRCDIR([dudders.c])
AC_CONFIG_AUX_DIR([scripts])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip subdir-objects])
AC_CONFIG_HEADER([config.h])

# Extra directory targets.
plugindir=`(
  test "x$prefix" = xNONE && prefix=$ac_default_prefix
  test "x$exec_prefix" = xNONE && exec_prefix=${prefix}
  eval echo "$libdir/dudders")`
AC_DEFINE_UNQUOTED([PLUGIN_DIR], "$plugindir",
  [Plugin installation directory])
AC_SUBST([plugindir])

# Checks for programs.
AC_PROG_CC([clang gcc cl cc])
AC_PROG_CC_C99
AM_PROG_CC_C_O
LT_INIT([dlopen])
LT_SYS_MODULE_EXT

AC_ARG_VAR([OPENSSL_CPPFLAGS],
  [C preprocessor flags for compiling with OpenSSL, e.g. -I<dir>])
AC_ARG_VAR([OPENSSL_LDFLAGS],
  [linker flags for linking against OpenSSL, e.g. -L<dir>])


AS_IF([test "x$ac_cv_prog_cc_stdc" = xno],
  [AC_MSG_FAILURE([get a C99 compliant compiler])])

# Choose some crypto libraries.
AC_ARG_WITH([crypto],
  [AS_HELP_STRING([--with-crypto=@<:@PACKAGE@:>@],
    [use PACKAGE for cryptography @<:@default="openssl"@:>@])],[],
  [with_crypto=openssl])
AC_ARG_WITH([dlcrypto],
  [AS_HELP_STRING([--with-dlcrypto=@<:@LIST@:>@],
    [use the plugins in LIST for cryptography @<:@default="openssl gcrypt"@:>@])],
    [],
    [with_dlcrypto="openssl gcrypt"])

AM_CONDITIONAL([CRYPT_DL], [test "x$with_crypto" = "xdl"])
AM_CONDITIONAL([CRYPT_OPENSSL], [test "x$with_crypto" = "xopenssl"])
AM_CONDITIONAL([CRYPT_GCRYPT], [test "x$with_crypto" = "xgcrypt"])
DS_CHECK_CRYPTO([$with_crypto], [true do_not_touch_LIBS],
   [AC_MSG_ERROR([crypto package "$with_crypto" unuseable])])

DS_CHECK_DLCRYPTO([$with_dlcrypto],
   [AC_MSG_ERROR([crypto package "$ds_crypto_package" not found])],
   [AC_MSG_ERROR([no dynamic crypto libraries useable])])
AM_CONDITIONAL([CRYPT_OPENSSL_OR_DL_OPENSSL],
 [test "x$with_crypto" = "xopenssl" -o -n "$ds_crypt_dl_openssl"])
AM_CONDITIONAL([CRYPT_GCRYPT_OR_DL_GCRYPT],
 [test "x$with_crypto" = "xgcrypt" -o -n "$ds_crypt_dl_gcrypt"])

# Checks for libraries.
AC_SEARCH_LIBS([gethostbyname], [nsl], [],
   [AC_MSG_FAILURE([gethostbyname(3) is required])])

# Checks for header files.
AC_HEADER_RESOLV
AC_HEADER_STDC
AC_HEADER_TIME
dnl should fail if these headers are not found

AC_CHECK_HEADERS([limits.h stddef.h stdint.h stdlib.h string.h],,
  [AC_MSG_FAILURE([system lacks required standard C])])
AC_CHECK_HEADERS([unistd.h libgen.h],,
  [AC_MSG_FAILURE([system lacks required POSIX/BSD header])])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h netdb.h sys/socket.h ],,
  [AC_MSG_FAILURE([system lacks required internet header])])
AC_CHECK_HEADERS([resolv.h arpa/nameser.h],,
  [AC_MSG_FAILURE([don't know how to use system's resolver])])

# Late checks for libraries.
DS_LIB_RESOLV([],
  [AC_MSG_FAILURE([don't know how to link resolver library])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getopt],,
  [AC_MSG_FAILURE([can't use POSIX getopt])])
AC_CHECK_FUNCS([gethostbyname socket strerror])
DS_RESOLV_LINK([res_init],[res_init()],[],
  [AC_MSG_FAILURE([don't know how to get default nameserver])])
DS_RESOLV_LINK([res_send],
  [res_send(NULL, 0, NULL, 0)])
DS_RESOLV_LINK([res_mkquery],
  [res_mkquery(0, NULL, 0, 0, NULL, 0, NULL, NULL, 0)])
DS_RESOLV_LINK([dn_skipname],
  [dn_skipname(NULL, NULL)])
DS_RESOLV_LINK([dn_comp],
  [dn_comp(NULL, NULL, 0, NULL, NULL)])
DS_RESOLV_LINK([ns_put16], [ns_put16(0, NULL)])
DS_RESOLV_LINK([ns_put32], [ns_put32(0, NULL)])
DS_RESOLV_LINK([ns_get16], [ns_get16(NULL)])
DS_RESOLV_LINK([ns_get32], [ns_get32(NULL)])
DS_RESOLV_LINK([p_rcode], [p_rcode(0)])

# Checks for declarations.
DS_RES_NSADDR_LIST
DS_NAMESER_DECLS
AC_CHECK_DECLS([RES_TIMEOUT,RES_DFLRETRY],[],[],dnl
[[@%:@ifdef HAVE_RESOLV_H
@%:@include <resolv.h>
@%:@endif
]])

# Output.
AC_CONFIG_FILES([Makefile tests/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([configuration complete.])
