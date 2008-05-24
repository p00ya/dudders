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

# automake config.
AUTOMAKE_OPTIONS = foreign dist-bzip2 no-dist-gzip
ACLOCAL_AMFLAGS = -I m4

# targets.
SUBDIRS = tests
bin_PROGRAMS = dudders
man8_MANS = dudders.8
EXTRA_DIST = configure.ac dudders.8.in NOTES
MAINTAINERCLEANFILES = $(RM) configure Makefile.in tests/Makefile.in aclocal.m4 config.h.in scripts/depcomp scripts/install-sh scripts/missing

# dudders binary.
dudders_SOURCES = dudders.c dnsupdate.c dnssoa.c dns_send.c
dudders_SOURCES += hope.c
dudders_SOURCES += dnsupdate.h dnssoa.h dns_send.h
dudders_SOURCES += hope.h parse_pk.h crypt.h
dudders_SOURCES += rpl_nameser.h rpl_resolv.h rpl_resolv.c
dudders_LDADD = @LIBS@
dudders_LDFLAGS =
LIBS =

# libtool-assisted crypto plugins.
plugin_LTLIBRARIES =
noinst_LTLIBRARIES =

if CRYPT_DL
  dudders_SOURCES += crypt_dl.c

  crypt_openssl_la_SOURCES = crypt_openssl.c parse_pk.c
  crypt_gcrypt_la_SOURCES = crypt_gcrypt.c parse_pk.c

if CRYPT_DL_OPENSSL
    plugin_LTLIBRARIES += crypt_openssl.la
    dudders_LDFLAGS += -dlopen crypt_openssl.la

    crypt_openssl_la_LDFLAGS = -module -export-dynamic -avoid-version -shrext .so
    crypt_openssl_la_LDFLAGS += -lcrypto
endif
if CRYPT_DL_GCRYPT
    plugin_LTLIBRARIES += crypt_gcrypt.la
    dudders_LDFLAGS += -dlopen crypt_gcrypt.la

    crypt_gcrypt_la_CPPFLAGS = $(LIBGCRYPT_CFLAGS)
    crypt_gcrypt_la_LDFLAGS = -module -export-dynamic -avoid-version -shrext .so
    crypt_gcrypt_la_LDFLAGS += $(LIBGCRYPT_LIBS)
endif

else !CRYPT_DL
  dudders_SOURCES += parse_pk.c
if CRYPT_OPENSSL
    dudders_SOURCES += crypt_openssl.c
    dudders_LDADD += -lcrypto
endif
if CRYPT_GCRYPT
    dudders_SOURCES += crypt_gcrypt.c
    dudders_CPPFLAGS = $(LIBGCRYPT_CFLAGS)
    dudders_LDADD += $(LIBGCRYPT_LIBS)
endif
endif !CRYPT_DL
