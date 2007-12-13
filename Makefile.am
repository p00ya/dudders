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

# configure substitutions.
CRYPTO = @CRYPTO@

# targets.
SUBDIRS = tests
bin_PROGRAMS = dudders
man1_MANS = dudders.1
EXTRA_DIST = configure.ac dudders.1.in NOTES
MAINTAINERCLEANFILES = $(RM) configure Makefile.in tests/Makefile.in aclocal.m4 config.h.in scripts/depcomp scripts/install-sh scripts/missing

# dudders binary.
dudders_SOURCES = dudders.c dnsupdate.c dnssoa.c dns_send.c
dudders_SOURCES += hope.c parse_pk.c
dudders_SOURCES += dnsupdate.h dnssoa.h dns_send.h
dudders_SOURCES += hope.h parse_pk.h crypt.h
dudders_SOURCES += rpl_nameser.h rpl_resolv.h rpl_resolv.c
EXTRA_dudders_SOURCES = crypt_openssl.c crypt_gcrypt.c
dudders_DEPENDENCIES = crypt_$(CRYPTO).$(OBJEXT)
dudders_LDADD = crypt_$(CRYPTO).$(OBJEXT)
