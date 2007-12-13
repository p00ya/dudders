/* dnssoa.c -- DNS SOA request parsing
 *
 * Copyright 2007 Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#include "rpl_nameser.h"

#include <netdb.h>
#include <resolv.h>
#include "rpl_resolv.h"

#include "hope.h"

void
dnssoa_parse(char *zone, char *mname,
    const unsigned char *response, size_t rlen)
{
	*mname = 0;
	hope(NS_HFIXEDSZ < rlen,
	    "server returned incomplete SOA response");
	hope(NS_PACKETSZ >= rlen,
	    "SOA response unexpectedly large");
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
	int dnlen;
	int soa_offset = NS_HFIXEDSZ;
	while (question_count) {	
		int dnlen = dn_skipname(response + NS_HFIXEDSZ, eom);
		hope(0 < dnlen, strerror(errno));
		soa_offset += dnlen + 4;
		--question_count;
	}
	const unsigned char *dzone = response + soa_offset;
	dnlen = dn_expand(response, eom, dzone, zone, NS_MAXDNAME);
	hope(0 < dnlen, strerror(errno));

	dnlen = dn_skipname(dzone, eom);
	const unsigned char *dmname = dzone + dnlen + 10;
	dnlen = dn_expand(response, eom, dmname, mname, NS_MAXDNAME);
	hope(0 < dnlen, strerror(errno));
}
