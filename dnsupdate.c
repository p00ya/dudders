/* dnsupdate.c -- Write DNS UPDATE + SIG(0) message
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#include "rpl_nameser.h"
#include <resolv.h>
#include "rpl_resolv.h"

#include "crypt.h"
#include "hope.h"

/* Number of seconds until query signature expires. */
#define SIGNATURE_DURATION 300

/* dn_comp-style dnptrs: pointers to compressed domain names . */
static unsigned char *names[5]; // dn_comp dnptrs


/* Copy `length' octets from `src' to `dst'.  Return value is first
 * octet after the copied data. */
static inline
char *
wire_direct(char *dst, const char *src, size_t length)
{
	memcpy(dst, src, length);
	return dst + length;
}

/* Copy `u' to `dst' in network byte order.  Return the position in
 * `dst' after `u'.  The buffer should hold 2 octets. */
static inline
char *
wire_short(char *dst, uint16_t u)
{
	ns_put16(u, (unsigned char *)dst);
	return dst + sizeof(u);
}

/* Copy `u' to `dst' in network byte order.  Return the position in
 * `dst' after `u'.  The buffer should hold 4 octets. */
static inline
char *
wire_long(char *dst, uint32_t u)
{
	ns_put32(u, (unsigned char *)dst);
	return dst + sizeof(u);
}

/* Encode `name' (a dot-separated domain string) into a label sequence
 * in the buffer `dst'.  The buffer should be large enough to hold
 * `wire_domain_length(name)' octets.  The return value is the first
 * octet after the label sequence in the buffer.  `name' must not
 * end in a period. */
static char *
wire_domain(char *dst, const char *name)
{
	int i = dn_comp(name, (unsigned char *)dst, NS_MAXCDNAME,
	    names, names + sizeof(names));
	hope(-1 != i, strerror(errno));
	return dst + i;
}


// UPDATE MESSAGE //////////////////////////////////////////////////////

// Message is formed as update_1, zone name, update_2, domain name,
// update_3, update_4, signature.  Using this "fill-in-the-blank"
// character buffer approach avoids many annoying packing/endian
// serialisation issues.

enum {
	update_1_additional = 11, // LSB of additional record count
};

// dnsupdate header
static const char update_1[] =
{
	0, 0, // id, to be overwritten
	0x28, 0, // DNS_QUERY, DNS_OPCODE_UPDATE
	0, 1, // 1 zone
	0, 0, // 0 prerequisites
	0, 2, // 2 update RRs (delete, add)
	0, 1, // 1 additional RR (sig)
};

// end of zone section
static const char update_2[] =
{
	0, ns_t_soa, // type
	0, ns_c_in,  // class
};

enum {
	update_3_domain = 10,
	update_3_ttl = 16,
	update_3_addr = 22,
};

static const char update_3[] =
{
	// update delete
	0, ns_t_a, // type
	0, ns_c_any, // class
	0, 0, 0, 0, // ttl (delete request)
	0, 0, // rdlength: no rdata

	// update add
	NS_CMPRSFLGS, 0, // compressed name, to be overwritten
	0, ns_t_a, // type
	0, ns_c_in, // class
	0, 0, 0, 0, // ttl, to be overwritten
	0, 4, // rdlength
	0, 0, 0, 0, // ip address, to be ovewritten
};

enum {
	update_4_rdlength = 9, // offset of rdata length
	update_4_rdata = 11,
	update_4_sigexpire = 11 + NS_SIG_EXPIR, // expiry time
	update_4_sigincept = 11 + NS_SIG_SIGNED, // inception time
	update_4_foot = 11 + NS_SIG_FOOT, // offset of key footprint
	update_4_signer = 11 + NS_SIG_SIGNER, // offset of signer id
	update_4_sig = 31, // offset of actual signature
//	sig0_fixed_rdata = 20, // octets of fixed rdata
};

static const char update_4[] = {
	// sig
	0, // name, not important
	0, ns_t_sig, // type
	0, ns_c_any, // class
	0, 0, 0, 0, // ttl
	0, 0, // rdlength, to be overwritten

	// rdata, see RFC2535 4.1 and NS_SIG_* in nameser.h
	0, 0, // type flags
	NS_ALG_MD5RSA, // algorithm
	0, // labels
	0, 0, 0, 0, // original TTL
	0, 0, 0, 0, // sig expiration, to be overwritten
	0, 0, 0, 0, // sig inception, to be overwritten
	0, 0, // key id (RFC2535 4.1.6), to be overwritten
	// then signer's name
};

// See dnsupdate.h
char *
wire_dnsupdate_message(char *dst, const char *zone, const char *domain,
    struct in_addr addr, uint32_t ttl)
{
	char *base = dst, *dom, *base3;
	names[0] = (unsigned char *)base;
	dst = wire_direct(dst, update_1, sizeof(update_1));
	wire_short(base, rand());
	dst = wire_domain(dst, zone);
	dst = wire_direct(dst, update_2, sizeof(update_2));
	dom = dst;
	dst = wire_domain(dst, domain);
	base3 = dst;
	dst = wire_direct(dst, update_3, sizeof(update_3));
	// add the same entry we deleted; do the compression manually
	// because we only allocated two octets for it.
	uint16_t compressed_domain = (dom - base) | (NS_CMPRSFLGS << 8);
	wire_short(base3 + update_3_domain, compressed_domain);
	wire_long(base3 + update_3_ttl, ttl);
	memcpy(base3 + update_3_addr, (char *)&addr, 4);
	return dst;
}

// See dnsupdate.h
char *
sign_query(char *dst, const char *query,
    const char *rr_start)
{
	assert(query < rr_start && rr_start < dst);

	// cut a payload so that the sig(0) RDATA appears before the
	// unsigned request (see RFC2931 3.1, RFC2535 4.1.8).
	size_t rdata_length = dst - rr_start - update_4_rdata;
	size_t payload_length = rdata_length + rr_start - query;
	char *payload = xmalloc(payload_length);
	memcpy(payload, rr_start + update_4_rdata, rdata_length);
	memcpy(payload + rdata_length, query, rr_start - query);
	payload[rdata_length + update_1_additional] = 0;
	crypt_sign(dst, payload, payload_length);
	free(payload);
	return dst + crypt_sign_length();
}

// See dnsupdate.h
char *
sign_dnsupdate_message(char *dst, const char *query,
    const char *keyname)
{
	char *rr_start = dst; // start of sig(0) record
	wire_direct(dst, update_4, sizeof(update_4));
	wire_short(dst + update_4_foot, crypt_footprint());

	uint32_t t = (uint32_t)time(NULL);
	wire_long(dst + update_4_sigexpire, t + SIGNATURE_DURATION);
	wire_long(dst + update_4_sigincept, t - SIGNATURE_DURATION / 2);

	// RFC2535 4.1.7 allows the signer's name to be compressed,
	// but BIND9 returns server failure if it is.
	names[1] = NULL;
	dst = wire_domain(dst + update_4_signer, keyname);
	dst = sign_query(dst, query, rr_start);
	wire_short(rr_start + update_4_rdlength,
	    dst - rr_start - update_4_rdata);

	return dst;
}

enum {
	response_flags = 2, // offset of first flag octet
};

// See dnsupdate.h
void
check_dnsupdate_response(const unsigned char *response, size_t length)
{
	hope(NS_HFIXEDSZ <= length,
	    "server returned incomplete DNS UPDATE response");
	uint16_t flags = ns_get16(response + response_flags);
	hope(0xa800 == (flags & 0xff00),
	    "possible spurious DNS UPDATE response");
	hope2(0 == (flags & 0x000f),
	    "DNS UPDATE error", p_rcode(flags & 0x000f));
}
