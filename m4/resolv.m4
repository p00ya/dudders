## resolv.m4 - autoconf checks for resolver(3)                -*- Autoconf -*-
## Copyright 2007 Dean Scarff
##
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License.  You
## may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

# See NOTES for the sordid details of resolver portability.

# DS_LIB_RESOLV([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------------------
#
# Check for the presence of the resolv library.  If the library is
# found, the shell variable `ds_lib' is set to the library flags
# required for resolver, and the same flags are added to LIBS, and
# ACTION-IF-FOUND is called.  Otherwise, ACTION-IF-NOT-FOUND is
# called.
#
# This is harder than just using AC_CHECK_LIB because it is common for
# the standard library functions from resolver(3) to in fact be
# proxies for those defined in libresolv.  Hence header and function
# checks may work but linking will fail.
AC_DEFUN([DS_LIB_RESOLV],
[AC_CACHE_CHECK([for resolver library linker flags],
  [ds_cv_lib_resolv],
  [AC_LANG_CONFTEST([AC_LANG_PROGRAM([[
@%:@if HAVE_SYS_TYPES_H
@%:@include <sys/types.h>
@%:@endif
@%:@if HAVE_NETINET_IN_H
@%:@include <netinet/in.h>
@%:@endif
@%:@if HAVE_ARPA_NAMESER_H
@%:@include <arpa/nameser.h>
@%:@endif
@%:@include <resolv.h>
]], [[res_query(NULL, 0, 0, NULL, 0)]])])
  ds_save_lib_resolv_LIBS=$LIBS
  for ds_lib in "" "-lresolv " ; do
    LIBS="${ds_lib}${ds_save_lib_resolv_LIBS}"
    AC_LINK_IFELSE([], [ds_cv_lib_resolv="$ds_lib" ; break],
      [ds_cv_lib_resolv="not possible"])
  done
  rm conftest.$ac_ext
  AS_IF([test -z "$ds_cv_lib_resolv"], [ds_cv_lib_resolv="nothing needed"],
    [test "$ds_cv_lib_resolv" = "not possible"],
    [LIBS=$ds_save_lib_resolv_LIBS])])
  AS_IF([test "$ds_cv_lib_resolv" = "not possible"], [$2], [$1])
])

# DS_NAMESER_DECLS([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ----------------------------------------------------------
#
# Instigate checks for various constant declarations from
# arpa/nameser.h.  AC_CHECK_DECLS is called with ACTION-IF-FOUND and
# ACTION-IF-NOT-FOUND for those declarations we use.
AC_DEFUN([DS_NAMESER_DECLS],
[AC_CHECK_DECLS(dnl
[NS_MAXDNAME, NS_MAXCDNAME, NS_MAXLABEL, NS_HFIXEDSZ, NS_PACKETSZ,
 NS_CMPRSFLGS, NS_DEFAULTPORT,
 NS_SIG_EXPIR, NS_SIG_SIGNED, NS_SIG_FOOT, NS_SIG_SIGNER,
 NS_ALG_MD5RSA, NS_MD5RSA_MAX_BASE64,
 ns_o_query, ns_c_in, ns_c_any, ns_t_soa, ns_t_sig], [$1], [$2],
[@%:@ifdef HAVE_SYS_TYPES_H
@%:@include <sys/types.h>
@%:@endif
@%:@ifdef HAVE_NETINET_IN_H
@%:@include <netinet/in.h>
@%:@endif
@%:@ifdef HAVE_ARPA_NAMESER_H
@%:@include <arpa/nameser.h>
@%:@endif
])])

# DS_RESOLV_LINK(DESC, [BODY], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ----------------------------------------------------------------------
#
# Check that a program including the source BODY can be linked, given
# the resolver headers are included in the prologue.  DESC should
# succinctly describe the symbol or function whose presence is being
# tested.  HAVE_DESC will be AC_DEFINE'd to 1 if the check succeeds.
#
# Run this check *after* DS_LIB_RESOLV.
AC_DEFUN([DS_RESOLV_LINK],
[AC_CACHE_CHECK([for resolver's $1 availability],
  [ds_cv_lib_resolv_$1],
  [AC_LINK_IFELSE([AC_LANG_PROGRAM([[
@%:@if HAVE_STDLIB_H
@%:@include <stdlib.h>
@%:@endif
@%:@if HAVE_SYS_TYPES_H
@%:@include <sys/types.h>
@%:@endif
@%:@if HAVE_NETINET_IN_H
@%:@include <netinet/in.h>
@%:@endif
@%:@if HAVE_ARPA_NAMESER_H
@%:@include <arpa/nameser.h>
@%:@endif
@%:@include <resolv.h>
]], [[$2]])],
  [ds_cv_lib_resolv_$1=yes],
  [ds_cv_lib_resolv_$1=no])])
  AS_IF([test "${ds_cv_lib_resolv_$1}" = yes],
  [AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_$1]), [1],
    [Define to 1 if resolver's $1 is callable.])
   $3], [$4])
])


# DS_RES_NSADDR_LIST
# ------------------
#
# Check that resolver's `_res' has a member named `nsaddr_list'.
AC_DEFUN([DS_RES_NSADDR_LIST],
[AC_CHECK_DECLS([_res.nsaddr_list], [], [],
[@%:@ifdef HAVE_SYS_TYPES_H
@%:@include <sys/types.h>
@%:@endif
@%:@ifdef HAVE_NETINET_IN_H
@%:@include <netinet/in.h>
@%:@endif
@%:@ifdef HAVE_ARPA_NAMESER_H
@%:@include <arpa/nameser.h>
@%:@endif
@%:@include <resolv.h>
])])
