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

# targets.
EXTRA_DIST = Ktest.+001+21102.private Ktest.+001+21102.key

# These are unit tests.
check_PROGRAMS = test-decode64 test-parse_pk
TESTS = test-decode64 test-parse_pk

noinst_HEADERS = test.h

# test program build rules.

test_decode64_SOURCES = test-decode64.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c

test_parse_pk_SOURCES = test-parse_pk.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c

test_sign_query_SOURCES = test-sign_query.c $(top_srcdir)/dnsupdate.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c

if CRYPT_OPENSSL_OR_DL_OPENSSL
TESTS += test-crypt-openssl test-sign_query-openssl
check_PROGRAMS += test-crypt-openssl test-sign_query-openssl
test_crypt_openssl_SOURCES = $(top_srcdir)/crypt_openssl.c
test_crypt_openssl_SOURCES += test-crypt.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c
test_crypt_openssl_LDADD = -lcrypto

test_sign_query_openssl_SOURCES = $(test_sign_query_SOURCES) $(top_srcdir)/crypt_openssl.c
test_sign_query_openssl_LDADD = -lcrypto
endif

if CRYPT_GCRYPT_OR_DL_GCRYPT
TESTS += test-crypt-gcrypt test-sign_query-gcrypt
check_PROGRAMS += test-crypt-gcrypt test-sign_query-gcrypt
test_crypt_gcrypt_SOURCES = $(top_srcdir)/crypt_gcrypt.c
test_crypt_gcrypt_SOURCES += test-crypt.c $(top_srcdir)/parse_pk.c $(top_srcdir)/hope.c test.c
test_crypt_gcrypt_LDADD = -lgcrypt

test_sign_query_gcrypt_SOURCES = $(test_sign_query_SOURCES) $(top_srcdir)/crypt_gcrypt.c
test_sign_query_gcrypt_LDADD = -lgcrypt
endif
