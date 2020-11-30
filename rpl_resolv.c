/* rpl_resolv.c -- replacement resolver functions
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
#include "config.h"
#endif

#include <string.h>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "rpl_nameser.h"

#include "hope.h"

// Domain names are a sequence of labels, possibly suffix-linked to
// each other.  See RFC1035 3.3 and 4.1.4.
#ifndef HAVE_DN_SKIPNAME
int
dn_skipname(const char *dnbegin, const char *eom)
{
	const char *p = dnbegin;
	while (p < eom) {
		if (!*p)
			return 1 + p - dnbegin;
		if (*p & NS_CMPRSFLGS)
			return 2 + p - dnbegin;
		p += *p & ~(unsigned char)(NS_CMPRSFLGS);
		++p;
	}
	return -1;
}
#endif /* !defined(HAVE_DN_SKIPNAME) */

#ifndef HAVE_DN_COMP
int
dn_comp(const char *name, unsigned char *dn_enc, int length,
    unsigned char **dnptrs, unsigned char **lastdnptr)
{
	// no compression is actually performed here
	hope(name && strlen(name) <= NS_MAXCDNAME,
	    "domain name exceeds limit"); // See RFC1035 3.1

	unsigned char *dst = dn_enc;
	for (;;) {
		unsigned char *d = dst;
		const char *s = name;
		while ('.' != *s && *s)
			*++d = *s++;

		hope2(s - name <= NS_MAXLABEL, name,
		    "domain name label exceeds limit"); //  RFC1035 2.3.1
		*dst = (unsigned char)(s - name);
		if (!*s) {
			// silently add root if name not dot-terminated
			if (s != name)
				*++d = 0;
			return 1 + d - dn_enc;
		}
		dst = ++d;
		name = ++s;
	}
}
#endif /* !defined(HAVE_DN_COMP) */


// See RFC1035 4.1.1 RCODE
#ifndef HAVE_P_RCODE
const char *rcode_strings[] = { "No error", "Format error", "Server failure",
	"Name error", "Not implemented", "Refused", "Unknown" };
#endif /* !defined(HAVE_P_RCODE) */
