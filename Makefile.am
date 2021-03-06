# Makefile.am -- Makefile template
# Copyright Dean Scarff
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.

# Makefile.am is handmade.
# automake produces Makefile.in from Makefile.am.
# configure produces Makefile from Makefile.in.

# automake config.
# See also AM_INIT_AUTOMAKE in configure.ac
ACLOCAL_AMFLAGS = -I m4

# targets.
SUBDIRS = tests
bin_PROGRAMS = dudders
man8_MANS = dudders.8
EXTRA_DIST = configure.ac NOTES
MAINTAINERCLEANFILES = $(RM) configure Makefile.in tests/Makefile.in aclocal.m4 config.h.in scripts/depcomp scripts/install-sh scripts/missing

# dudders binary.
dudders_SOURCES = dudders.c dnsupdate.c dnssoa.c dns_send.c
dudders_SOURCES += hope.c
dudders_SOURCES += dnsupdate.h dnssoa.h dns_send.h
dudders_SOURCES += hope.h parse_pk.h crypt.h
dudders_SOURCES += rpl_nameser.h rpl_resolv.h rpl_resolv.c
dudders_CPPFLAGS =
dudders_LDADD = @LIBS@
dudders_LDFLAGS =
LIBS =

# libtool-assisted crypto plugins.
plugin_LTLIBRARIES =
noinst_LTLIBRARIES =

if CRYPT_DL
  dudders_SOURCES += crypt_dl.c
  dudders_LDFLAGS += -rpath @plugindir@

  crypt_openssl_la_SOURCES = crypt_openssl.c parse_pk.c hope.c
  crypt_gcrypt_la_SOURCES = crypt_gcrypt.c parse_pk.c hope.c

if CRYPT_DL_OPENSSL
    plugin_LTLIBRARIES += crypt_openssl.la

    crypt_openssl_la_CPPFLAGS = $(OPENSSL_CPPFLAGS)
    crypt_openssl_la_LDFLAGS = -module -export-dynamic -avoid-version
    crypt_openssl_la_LDFLAGS += $(OPENSSL_LDFLAGS) -lcrypto
endif
if CRYPT_DL_GCRYPT
    plugin_LTLIBRARIES += crypt_gcrypt.la

    crypt_gcrypt_la_CPPFLAGS = $(LIBGCRYPT_CFLAGS)
    crypt_gcrypt_la_LDFLAGS = -module -export-dynamic -avoid-version
    crypt_gcrypt_la_LDFLAGS += $(LIBGCRYPT_LIBS)
endif

else !CRYPT_DL
  dudders_SOURCES += parse_pk.c
if CRYPT_OPENSSL
    dudders_SOURCES += crypt_openssl.c
    dudders_CPPFLAGS += $(OPENSSL_CPPFLAGS)
    dudders_LDFLAGS += $(OPENSSL_LDFLAGS)
    dudders_LDADD += -lcrypto
endif
if CRYPT_GCRYPT
    dudders_SOURCES += crypt_gcrypt.c
    dudders_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
    dudders_LDADD += $(LIBGCRYPT_LIBS)
endif
endif !CRYPT_DL
