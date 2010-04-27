/* dnsupdate.h -- Write DNS UPDATE + SIG(0) message
 *
 * Copyright 2007--2010 Dean Scarff
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

#ifndef DNSUPDATE_H
# define DNSUPDATE_H

# ifdef HAVE_CONFIG_H
#  include "config.h"
# endif

# include <netinet/in.h>

/* Write a DNS UPDATE request to `dst'.  The request will be to delete
 * an A record for `domain' in `zone', then add it again with the
 * address `addr' and time to live of `ttl' seconds.  Returns the
 * first octet after the message. */
unsigned char *wire_dnsupdate_message(unsigned char *dst,
    const char *zone, const char *domain, struct in_addr addr, uint32_t ttl);

/* Sign `query' by writing the cryptographic signature to `dst'.
 * `query' is the full query except for the signature field of the
 * SIG(0) record at the very end.  The SIG(0) record of `query' must
 * begin at `rr_start'; and this record's signature field at `dst'.
 * Returns the first octet after the signed query (which is therefore
 * also the end of the SIG(0) record and the SIG(0) record's
 * signature). */
unsigned char *sign_query(unsigned char *dst,
    const char *query, const char *rr_start);

/* Append a SIG(0) RR to the end of `query' (pointed to by `dst') and
 * adjust the payload RR counts.  The key should identify the entity
 * given by `keyname', which is assumed to be a domain name.  Returns
 * the first octet after the signed message. */
unsigned char *sign_dnsupdate_message(unsigned char *dst,
    unsigned char *query, const char *keyname);

/* Check that `response', of `length' octets, indicates that a message
 * generated with `wire_dnsupdate_message' was successful. */
void check_dnsupdate_response(const unsigned char *response, size_t length);

#endif /* !defined(DNSUPDATE_H) */
