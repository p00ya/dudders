## crypto.m4 - checks for crypto libraries                    -*- Autoconf -*-
## Copyright Dean Scarff
##
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License.


# DS_WITH_OPENSSL(ACTION)
# ----------------------------------
#
# Add OPENSSL_CPPFLAGS and OPENSSL_LDFLAGS to CPPFLAGS and LDFLAGS
# respectively, before ACTION.  After ACTION, CPPFLAGS and LDFLAGS are
# restored.
AC_DEFUN([DS_WITH_OPENSSL],[
AS_IF([test "x$OPENSSL_CPPFLAGS" != "x"],
  [ds_save_cppflags=${CPPFLAGS}
  CPPFLAGS="${CPPFLAGS} ${OPENSSL_CPPFLAGS}"])
AS_IF([test "x$OPENSSL_LDFLAGS" != "x"],
  [ds_save_ldflags=${LDFLAGS}
  LDFLAGS="${LDFLAGS} ${OPENSSL_LDFLAGS}"])
$1
AS_IF([test "x$OPENSSL_CPPFLAGS" != "x"],[CPPFLAGS=${ds_save_cppflags}])
AS_IF([test "x$OPENSSL_LDFLAGS" != "x"],[LDFLAGS=${ds_save_ldflags}])
])


# DS_CHECK_CRYPTO(PACKAGE, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------
#
# Check that the libraries required for the crypto package PACKAGE are
# available.
#
# `LT_INIT([dlopen])' should be called before `DS_CHECK_CRYPTO'.
AC_DEFUN([DS_CHECK_CRYPTO],
[AS_CASE([$1],[dl],
  [LIBS="$lt_cv_dlopen_libs $LIBS"],dnl because we don't use libltdl
  [openssl],
  [DS_WITH_OPENSSL([AC_CHECK_LIB([crypto], [RSA_sign], [$2], [$3])])],
  [gcrypt],
  [AM_PATH_LIBGCRYPT([1.2.0], [$2], [$3])],
  [AC_MSG_ERROR([unknown crypto package "$with_crypto"])])
])


# DS_CHECK_DLCRYPTO(DL-PACKAGES, [ACTION-IF-MISSING], [ACTION-IF-NONE])
# ---------------------------------------------------------------------
#
# Check for libraries from the whitespace separated list DL-PACKAGES.
# The symbols `CRYPT_DL_package' will be defined for each package
# found in DL-PACKAGES, with contiguous values from zero in the order
# they appeared in DL-PACKAGES.  The symbol `CRYPT_DL_COUNT' will be
# defined to the number of (useable) packages in PACKAGES.
#
# AM_CONDITIONAL for CRYPT_DL_package is called for all known
# packages.  The shell variable `ds_crypt_dl_PACKAGE' is set to the
# priority of all packages found.
#
# If a specified package is missing, ACTION-IF-MISSING is called.  The
# missing package's name will be available in the shell variable
# `ds_crypto_package'.
#
# If no useable packages were found, ACTION-IF-NONE is called.
#
# These tests are all silently ignored if the shell variable
# with_crypto isn't "dl".
AC_DEFUN([DS_CHECK_DLCRYPTO],[
AS_IF([test "x$with_crypto" = "xdl"],
  [ds_i=0
  ds_save_libs=$LIBS
  for ds_crypto_package in $1 ; do
    AS_CASE(["$ds_crypto_package"],[openssl],
      [DS_WITH_OPENSSL(
        [AC_CHECK_LIB([crypto], [RSA_sign],
         [ds_crypt_dl_openssl=$ds_i
          AC_DEFINE_UNQUOTED([CRYPT_DL_OPENSSL], [$ds_crypt_dl_openssl],
           [Define to the priority of the OpenSSL crypto plugin.])
          ds_i=$(($ds_i+1))],
         [$2])])],
      [gcrypt],
      [AM_PATH_LIBGCRYPT([1.2.0],
       [ds_crypt_dl_gcrypt=$ds_i
        AC_DEFINE_UNQUOTED([CRYPT_DL_GCRYPT], [$ds_crypt_dl_gcrypt],
         [Define to the priority of the gcrypt crypto plugin.])
        ds_i=$(($ds_i+1))],
       [$2])],
    [AC_MSG_WARN(["$ds_crypto_package" is not a supported crypto package])])
  done
  LIBS=$ds_save_libs
  AC_DEFINE_UNQUOTED([CRYPT_DL_COUNT], [$ds_i],
    [Define to the number of crypto modules])
  AS_IF([test 0 -eq "$ds_i"], [$3])])
AM_CONDITIONAL([CRYPT_DL_OPENSSL], [test -n "$ds_crypt_dl_openssl"])
AM_CONDITIONAL([CRYPT_DL_GCRYPT], [test -n "$ds_crypt_dl_gcrypt"])
])
