/* dnssoa.c -- DNS SOA request parsing
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "rpl_nameser.h"

#include <netdb.h>
#include <resolv.h>
#include "rpl_resolv.h"

#include "hope.h"

/* Check that the `dn_skipname' or `dn_expand' return value `dnlen' is
 * okay, and that it is followed by a SOA IN identifier.  Returns a
 * pointer to after the SOA/IN identifiers if they were present, or
 * NULL. */
static const unsigned char *
check_dn_soa(int dnlen, const unsigned char *dn, const unsigned char *eom)
{
	hope(0 < dnlen, strerror(errno));
	hope(dn + dnlen + 4 < eom, "SOA response ended prematurely");
	if (ns_t_soa != ns_get16(dn + dnlen))
		return NULL;
	if (ns_c_in != ns_get16(dn + dnlen + 2))
		return NULL;
	return dn + 4 + dnlen;
}

// See dnssoa.h
void
dnssoa_parse(
    char *zone, char *mname, const unsigned char *response, size_t rlen)
{
	*mname = 0;
	hope(NS_HFIXEDSZ < rlen, "server returned incomplete SOA response");
	hope(NS_PACKETSZ >= rlen, "SOA response unexpectedly large");
	const unsigned char *eom = response + rlen;

	uint16_t flags = ns_get16(response + 2);
	if (0x8000 != (flags & 0xf80f))
		return; // not looking at a response

	uint16_t question_count = ns_get16(response + 4);
	uint16_t response_count = ns_get16(response + 6);
	uint16_t authority_count = ns_get16(response + 8);
	if (1 != question_count)
		return;
	if (1 != response_count &&
	    !(0 == response_count && 1 == authority_count))
		return;

	// skip over query section
	const unsigned char *authority = response + NS_HFIXEDSZ;
	int dnlen = dn_skipname(authority, eom);
	authority = check_dn_soa(dnlen, authority, eom);
	if (!authority)
		return;

	dnlen = dn_expand(response, eom, authority, zone, NS_MAXDNAME);
	const unsigned char *dmname = check_dn_soa(dnlen, authority, eom);
	dmname += 6;

	dnlen = dn_expand(response, eom, dmname, mname, NS_MAXDNAME);
	hope(0 < dnlen, strerror(errno));
}
