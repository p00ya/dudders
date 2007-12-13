# Makefile.am -- Makefile template
# Copyright 2007 Dean Scarff
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makefile.am is handmade.
# automake produces Makefile.in from Makefile.am.
# configure produces Makefile from Makefile.in.

# configure substitutions
CRYPTO = @CRYPTO@
LIBCRYPTO = @LIBCRYPTO@

# targets.
EXTRA_DIST = Ktest.+001+21102.private Ktest.+001+21102.key

# These are unit tests.
check_PROGRAMS = test-decode64 test-parse_pk test-crypt test-sign_query
TESTS = test-decode64 test-parse_pk test-crypt test-sign_query

noinst_HEADERS = test.h

# test program build rules.

test_crypt_SOURCES = test-crypt.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c
EXTRA_test_crypt_SOURCES = $(top_srcdir)/crypt_openssl.c $(top_srcdir)/crypt_gcrypt.c
test_crypt_DEPENDENCIES = $(top_srcdir)/crypt_$(CRYPTO).$(OBJEXT)
test_crypt_LDADD = $(top_srcdir)/crypt_$(CRYPTO).$(OBJEXT)

test_decode64_SOURCES = test-decode64.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c

test_parse_pk_SOURCES = test-parse_pk.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c

test_sign_query_SOURCES = test-sign_query.c $(top_srcdir)/dnsupdate.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c
EXTRA_test_sign_query_SOURCES = $(top_srcdir)/crypt_openssl.c $(top_srcdir)/crypt_gcrypt.c
test_sign_query_DEPENDENCIES = $(top_srcdir)/crypt_$(CRYPTO).$(OBJEXT)
test_sign_query_LDADD = $(top_srcdir)/crypt_$(CRYPTO).$(OBJEXT)
